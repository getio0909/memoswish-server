//! 内部资产身份、上传证据和引用；不存交付 URL 或任意 provider 载荷。

use crate::jobs::{AssetJobRepo, JobClaim};
use crate::{CoreError, CoreResult, Principal};
use async_trait::async_trait;

/// 已发布资产的只读交付证据；URL 不参与身份判断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetDelivery {
    pub asset_id: String,
    pub spec: AssetSpec,
    pub key: String,
    pub store_id: String,
    pub version: ObjectVersion,
}

/// 遍历卡片中所有可下载资产，预取和授权使用相同位置集合。
pub fn card_assets(card: &memoswish_protocol::Card) -> Vec<&memoswish_protocol::AssetRef> {
    let mut out = Vec::new();
    for face in [&card.front, &card.back] {
        out.extend(face.blocks.iter().filter_map(|b| b.asset()));
    }
    out.extend(card.visual.image.iter());
    if let Some(tts) = &card.tts {
        out.push(&tts.audio);
    }
    if let Some(bgm) = &card.bgm {
        out.push(&bgm.track.asset);
    }
    out
}

/// 资产位置稳定命名，导入引用与卡片中实际资产逐项对应。
pub fn card_asset_slots_mut(card: &mut memoswish_protocol::Card) -> Vec<(String, &mut memoswish_protocol::AssetRef)> {
    let mut out = Vec::new();
    for (name, face) in [("front", &mut card.front), ("back", &mut card.back)] {
        for (i, block) in face.blocks.iter_mut().enumerate() {
            if let memoswish_protocol::ContentBlock::Image { asset, .. } = block {
                out.push((format!("{name}-{i}"), asset));
            }
        }
    }
    if let Some(asset) = &mut card.visual.image {
        out.push(("visual".into(), asset));
    }
    if let Some(tts) = &mut card.tts {
        out.push(("tts".into(), &mut tts.audio));
    }
    if let Some(bgm) = &mut card.bgm {
        out.push(("bgm".into(), &mut bgm.track.asset));
    }
    out
}

/// 校验来自历史 JSON 的元数据，不能依赖 URL 或文件名提供完整性。
pub fn validate_asset_ref(asset: &memoswish_protocol::AssetRef) -> CoreResult<()> {
    crate::store::validate_key(&asset.key)?;
    AssetSpec { mime: asset.mime.clone(), size: i64::try_from(asset.bytes).unwrap_or(-1), sha256: asset.sha256.clone() }
        .validate()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetSpec {
    pub mime: String,
    pub size: i64,
    pub sha256: String,
}

impl AssetSpec {
    pub fn validate(&self) -> CoreResult<()> {
        if !(0..=64 * 1024 * 1024).contains(&self.size)
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.mime.len() > 128
            || self.mime.split('/').count() != 2
            || self.mime.split('/').any(str::is_empty)
            || !self.mime.bytes().all(|b| b.is_ascii_alphanumeric() || b"/.-+".contains(&b))
        {
            return Err(CoreError::invalid("invalid asset metadata"));
        }
        Ok(())
    }
}

/// Unknown 不能传给 ObjectStore::delete_write；字面量 null 仍是精确版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectVersion {
    Unknown,
    Unversioned,
    VersionId(String),
}

impl ObjectVersion {
    pub fn validate(&self) -> CoreResult<()> {
        if let Self::VersionId(v) = self
            && (v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control))
        {
            return Err(CoreError::invalid("invalid object version"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetIntent {
    pub id: String,
    pub asset_id: String,
    pub spec: AssetSpec,
    pub published_attempt: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    InFlight,
    Uploaded,
    Uncertain,
    CleanupPending,
    Cleaned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadAttempt {
    pub id: String,
    pub intent_id: String,
    pub key: String,
    pub store_id: String,
    pub claim_token: String,
    pub outcome: UploadOutcome,
    pub version: ObjectVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetReference {
    pub asset_id: String,
    pub owner_id: String,
    pub slot: String,
}

/// 标识符限定为不携带 URL 的有界不透明值；错误不回显输入。
pub fn validate_asset_id(value: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(CoreError::invalid("invalid asset identifier"));
    }
    Ok(())
}

#[async_trait]
pub trait AssetRepo: AssetJobRepo + crate::tts::SpeechRepo + crate::bgm::BgmPublicationRepo {
    /// 缓存不是授权；读取者必须另行检查当前发布、引用与物理身份。
    async fn asset_read_manifest(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> CoreResult<Option<crate::asset_read::ReadManifest>>;
    /// 单租户每对象只留一个身份；不完整进度不能覆盖同身份的完整清单。
    async fn save_asset_read_manifest(
        &self,
        tenant_id: &str,
        key: &str,
        manifest: &crate::asset_read::ReadManifest,
    ) -> CoreResult<()>;
    /// 事务内重查读者双世代及当前角色，查询已发布且仍有引用的精确 attempt。
    async fn asset_delivery(
        &self,
        principal: &Principal,
        key: &str,
        permission: crate::Permission,
    ) -> CoreResult<Option<AssetDelivery>>;
    /// deprecated bridge 的候选集；返回后仍须逐字段验证业务资产引用。
    async fn legacy_asset_cards(&self, tenant_id: &str, key: &str) -> CoreResult<Vec<memoswish_protocol::Card>>;
    /// job、资产及 prepared intent 原子提交，幂等冲突不更改已有责任。
    async fn prepare_asset(
        &self,
        principal: &Principal,
        request_id: &str,
        spec: &AssetSpec,
        max_attempts: i64,
    ) -> CoreResult<AssetIntent>;
    async fn asset_intent(&self, tenant_id: &str, intent_id: &str) -> CoreResult<Option<AssetIntent>>;
    async fn begin_upload(&self, tenant_id: &str, claim: &JobClaim, store_id: &str) -> CoreResult<UploadAttempt>;
    /// 晚到回执可补充原 attempt 证据，但不获得新 claim 的发布权限。
    async fn record_upload(&self, tenant_id: &str, attempt: &UploadAttempt, version: &ObjectVersion) -> CoreResult<()>;
    async fn mark_upload_uncertain(&self, tenant_id: &str, attempt: &UploadAttempt) -> CoreResult<()>;
    async fn upload_attempts(&self, tenant_id: &str, intent_id: &str) -> CoreResult<Vec<UploadAttempt>>;
    async fn publish_asset(
        &self,
        principal: &Principal,
        claim: &JobClaim,
        attempt_id: &str,
        reference: &AssetReference,
    ) -> CoreResult<()>;
    async fn add_asset_reference(&self, principal: &Principal, reference: &AssetReference) -> CoreResult<()>;
    async fn remove_asset_reference(&self, principal: &Principal, owner_id: &str, slot: &str) -> CoreResult<()>;
    async fn asset_reference_count(&self, tenant_id: &str, asset_id: &str) -> CoreResult<i64>;
    /// 只清理从未发布的自有 attempt，不根据引用数启用孤儿 GC。
    async fn begin_asset_cleanup(
        &self,
        tenant_id: &str,
        claim: &JobClaim,
        attempt_id: &str,
        store_id: &str,
    ) -> CoreResult<UploadAttempt>;
    async fn record_asset_cleaned(&self, tenant_id: &str, attempt: &UploadAttempt) -> CoreResult<()>;
    /// 窄维护端口跨租户发现责任，包含 dead jobs；游标为完整复合身份。
    async fn unresolved_assets(
        &self,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> CoreResult<Vec<(String, AssetIntent)>>;
}

/// 历史导出保留未知正文，只清除已知资产槽位的交付 URL。
pub fn clear_historical_delivery_urls(card: &mut serde_json::Value) {
    for pointer in ["/visual/image", "/tts/audio", "/bgm/track/asset"] {
        if let Some(asset) = card.pointer_mut(pointer).and_then(serde_json::Value::as_object_mut) {
            asset.insert("url".into(), serde_json::Value::String(String::new()));
        }
    }
    for face in ["front", "back"] {
        if let Some(blocks) =
            card.get_mut(face).and_then(|f| f.get_mut("blocks")).and_then(serde_json::Value::as_array_mut)
        {
            for block in blocks {
                if block.get("type").and_then(serde_json::Value::as_str) == Some("image")
                    && let Some(asset) = block.get_mut("asset").and_then(serde_json::Value::as_object_mut)
                {
                    asset.insert("url".into(), serde_json::Value::String(String::new()));
                }
            }
        }
    }
}
