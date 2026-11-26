//! 便携导出与导入沿用 S20 读取证明及 S18 持久执行，不重新生成媒体。
use crate::{Services, asset_delivery};
use base64::{Engine, engine::general_purpose::STANDARD};
use memoswish_content::{
    deckpack::*,
    imports::{fingerprint, import_result},
};
use memoswish_core::{CoreError, CoreResult, Principal, assets::*, imports::*};
use memoswish_protocol::{Deck, PortableDeckPack, PortableMedia};

static PORTABLE_WORK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

impl Services {
    pub async fn export_portable_deck(
        &self,
        p: &Principal,
        id: &str,
        credential: Option<ImportCredential>,
    ) -> CoreResult<PortableDeckPack> {
        let _permit = PORTABLE_WORK
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("portable work capacity exhausted".into()))?;
        let deadline = tokio::time::Instant::now() + asset_delivery::DELIVERY_DEADLINE;
        tokio::time::timeout_at(deadline, async {
            let mut verified_keys = std::collections::HashSet::new();
            let mut physical_bytes = 0u64;
            let repo = self.content.import_repository();
            let authority = ImportAuthority::capture(p, credential);
            #[cfg(test)]
            tests::wait_at("snapshot").await;
            let mut content = repo.portable_snapshot(&authority, id).await?;
            for card in &mut content.cards {
                memoswish_content::imports::prepare_export_provenance(card)?;
            }
            content.version =
                if content.cards.iter().any(memoswish_core::bgm::has_media_metadata) { "1.2" } else { "1.1" }.into();
            let mut pack = PortableDeckPack {
                version: if content.version == "1.2" { "2.2" } else { "2.1" }.into(),
                content,
                media: vec![],
            };
            let mut total = 0usize;
            let mut blobs: std::collections::HashMap<(String, String, u64), String> = std::collections::HashMap::new();
            for card in &mut pack.content.cards {
                let owner = card.id.clone();
                memoswish_core::content_validation::validate_card(card)?;
                for (_, asset) in card_asset_slots_mut(card) {
                    validate_asset_ref(asset)?;
                    let identity = (asset.sha256.clone(), asset.mime.clone(), asset.bytes);
                    let next = if let Some(id) = blobs.get(&identity) {
                        id.clone()
                    } else {
                        total = total
                            .checked_add(
                                usize::try_from(asset.bytes).map_err(|_| CoreError::invalid("invalid asset size"))?,
                            )
                            .filter(|n| *n <= MEDIA_BYTES)
                            .ok_or_else(|| CoreError::Unsupported("portable media exceeds 8 MiB".into()))?;
                        if pack.media.len() >= BLOBS {
                            return Err(CoreError::Unsupported("portable media exceeds blob limit".into()));
                        }
                        format!("m{}", pack.media.len())
                    };
                    if tokio::time::Instant::now() >= deadline {
                        return Err(CoreError::Unavailable("portable export deadline exceeded".into()));
                    }
                    // 重复槽位仍检查当前引用；同一物理键的相同摘要只读取一次。
                    #[cfg(test)]
                    tests::wait_at("select").await;
                    let selected = asset_delivery::select(
                        repo.as_ref(),
                        self.media.store().as_ref(),
                        p,
                        &asset.key,
                        "content",
                        Some(&owner),
                    )
                    .await?;
                    if selected.spec.sha256 != asset.sha256
                        || selected.spec.size as u64 != asset.bytes
                        || selected.spec.mime != asset.mime
                    {
                        return Err(CoreError::Conflict("export attachment reference changed".into()));
                    }
                    if verified_keys.insert((asset.key.clone(), identity.clone())) {
                        physical_bytes =
                            physical_bytes.checked_add(asset.bytes).filter(|n| *n <= 64 * 1024 * 1024).ok_or_else(
                                || CoreError::Unsupported("portable export physical read budget exceeded".into()),
                            )?;
                        let object = asset_delivery::read(
                            repo.as_ref(),
                            self.media.store().as_ref(),
                            p,
                            &asset.key,
                            "content",
                            Some(&owner),
                        )
                        .await?;
                        if object.bytes.len() as u64 != asset.bytes
                            || object.mime != asset.mime
                            || memoswish_core::ids::sha256_hex(&object.bytes) != asset.sha256
                        {
                            return Err(CoreError::Conflict("export attachment integrity mismatch".into()));
                        }
                        if let std::collections::hash_map::Entry::Vacant(entry) = blobs.entry(identity) {
                            pack.media.push(PortableMedia {
                                id: next.clone(),
                                mime: asset.mime.clone(),
                                bytes: asset.bytes,
                                sha256: asset.sha256.clone(),
                                data_base64: STANDARD.encode(object.bytes),
                            });
                            entry.insert(next.clone());
                        }
                    }
                    asset.key = next;
                    asset.url.clear();
                }
            }
            // 所有源对象与槽位授权完成后才改写包内身份，数据库 UUID 与时间不占交换预算。
            let media_ids = portable_export_content(&mut pack.content);
            for media in &mut pack.media {
                media.id = media_ids[&media.id].clone();
            }
            validate(&pack)?;
            #[cfg(test)]
            tests::wait_at("revalidate").await;
            repo.revalidate_portable_export(&authority).await?;
            // 即使最终查询在期限之后恰好就绪，也不能返回过期的无媒体导出。
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::Unavailable("portable export deadline exceeded".into()));
            }
            Ok(pack)
        })
        .await
        .map_err(|_| CoreError::Unavailable("portable export deadline exceeded".into()))?
    }
    pub async fn import_portable_deck(
        &self,
        p: &Principal,
        pack: PortableDeckPack,
        key: Option<String>,
        credential: Option<ImportCredential>,
    ) -> CoreResult<Deck> {
        self.import_portable_deck_input(p, input_value(&pack)?, key, credential).await
    }
    /// 原始便携封套及 content 分别计量，默认字段不能挤占旧预算。
    pub async fn import_portable_deck_input(
        &self,
        p: &Principal,
        pack: serde_json::Value,
        key: Option<String>,
        credential: Option<ImportCredential>,
    ) -> CoreResult<Deck> {
        let permit = PORTABLE_WORK
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("portable work capacity exhausted".into()))?;
        self.auth.require_privacy_collection(p).await?;
        let identity_pack: PortableDeckPack = decode_input(pack.clone(), DOCUMENT_BYTES)?;
        let services = self.clone();
        let p = p.clone();
        self.operations
            .spawn(async move {
                let _permit = permit;
                input_json_bytes(&pack, DOCUMENT_BYTES)?;
                let authority = ImportAuthority::capture(&p, credential);
                let fingerprint = fingerprint("portable-deckpack", &identity_pack, false)?;
                let key = key.unwrap_or_else(memoswish_core::ids::new_id);
                validate_request_id(&key)?;
                let repo = services.content.import_repository();
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                let operation = match repo.lookup_import(&authority, &key, &fingerprint).await? {
                    Some(existing) => existing,
                    None => {
                        let work = services.content.prepare_portable_deck_pack(&p, pack)?;
                        let limit = services.quota.card_write_limit(&p.tenant_id).await?;
                        control.begin_acceptance()?;
                        repo.accept_import(
                            &authority,
                            &key,
                            &fingerprint,
                            &work,
                            limit,
                            services.content.import_staging_limit(),
                        )
                        .await?
                    }
                };
                control.accepted();
                let result = import_result(services.content.drive_import(&p.tenant_id, &operation.id).await?)?;
                serde_json::from_value(result).map_err(CoreError::internal)
            })?
            .await
            .map_err(|_| CoreError::Unavailable("import owner interrupted; retry original identity".into()))?
    }
}

#[cfg(test)]
#[path = "portable_deadline_tests.rs"]
mod tests;
