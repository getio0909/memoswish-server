//! 响应副本的交付地址与有界授权读取；不回写内容 revision 或历史 URL。

use memoswish_core::assets::{AssetDelivery, AssetSpec, ObjectVersion, card_assets, validate_asset_ref};
use memoswish_core::repo::Repository;
use memoswish_core::store::{ObjectStore, StoredObject, validate_key};
use memoswish_core::{CoreError, CoreResult, Permission, Principal};
use memoswish_protocol::{AssetRef, BgmTrack, Card, ContentBlock, FeedPage};

pub fn render_asset(asset: &mut AssetRef, surface: &str, owner: &str) {
    // 参数来自内部 ID，逐字节编码，不能把旧 URL 的凭据或 query 带入新地址。
    let encoded: String = owner.bytes().map(|b| format!("%{b:02X}")).collect();
    asset.url = format!("/assets/{}?delivery=1&surface={surface}&owner={encoded}", asset.key);
}

pub fn render_card(mut card: Card, surface: &str) -> Card {
    for face in [&mut card.front, &mut card.back] {
        for block in &mut face.blocks {
            if let ContentBlock::Image { asset, .. } = block {
                render_asset(asset, surface, &card.id);
            }
        }
    }
    if let Some(asset) = &mut card.visual.image {
        render_asset(asset, surface, &card.id);
    }
    if let Some(tts) = &mut card.tts {
        render_asset(&mut tts.audio, surface, &card.id);
    }
    if let Some(bgm) = &mut card.bgm {
        render_asset(&mut bgm.track.asset, surface, &card.id);
    }
    card
}

pub fn render_cards(cards: Vec<Card>, surface: &str) -> Vec<Card> {
    cards.into_iter().map(|card| render_card(card, surface)).collect()
}

pub fn render_bgm(mut track: BgmTrack) -> BgmTrack {
    render_asset(&mut track.asset, "media", &track.id);
    track
}

pub fn render_page(mut page: FeedPage) -> FeedPage {
    for item in &mut page.items {
        item.card = render_card(item.card.clone(), "feed");
    }
    for entry in &mut page.prefetch.entries {
        for asset in &mut entry.assets {
            render_asset(asset, "feed", &entry.card_id);
        }
    }
    page.prefetch.expires_at = None;
    page
}

pub fn permission(surface: &str) -> CoreResult<Permission> {
    match surface {
        "content" => Ok(Permission::ContentRead),
        "feed" => Ok(Permission::FeedRead),
        "media" => Ok(Permission::MediaRead),
        _ => Err(CoreError::invalid("invalid asset delivery surface")),
    }
}

/// 只有固定内置 Pad 是匿名公共资源；不能凭 shared 前缀创建 public 对象。
pub fn is_builtin(key: &str) -> bool {
    memoswish_media::bgm::PRESETS.iter().any(|preset| key == format!("shared/bgm/{}.wav", preset.0))
}

fn missing() -> CoreError {
    CoreError::NotFound("asset".into())
}

#[derive(Debug, Clone, PartialEq)]
pub struct SelectedDelivery {
    pub key: String,
    pub spec: AssetSpec,
    pub version: ObjectVersion,
    pub store_id: String,
    pub publication: Option<AssetDelivery>,
    pub reference: Option<AssetRef>,
    pub reference_owner: Option<String>,
    pub managed: bool,
}

/// 选定精确发布与业务引用；最终发头前必须比较同一投影。
pub async fn select(
    repo: &dyn Repository,
    store: &dyn ObjectStore,
    p: &Principal,
    key: &str,
    surface: &str,
    owner: Option<&str>,
) -> CoreResult<SelectedDelivery> {
    validate_key(key)?;
    let public = is_builtin(key);
    if !public && !key.starts_with(&p.asset_prefix()) {
        return Err(missing());
    }
    let perm = permission(surface)?;
    // 即使不是 S15 对象，此调用仍检查当前双世代及当前角色。
    let published = if public { None } else { repo.asset_delivery(p, key, perm).await? };
    let mut reference = None;
    let mut reference_owner = None;
    if (public || surface == "media")
        && let Some(track) = repo
            .list_bgm(&p.tenant_id)
            .await?
            .into_iter()
            .filter(|track| owner.is_none_or(|id| id == track.id) || public)
            .find(|track| track.asset.key == key)
    {
        reference_owner = Some(track.id);
        reference = Some(track.asset);
    }
    if reference.is_none() && !public && (surface != "media" || !p.can(Permission::ContentWrite)) {
        let cards = if let Some(owner) = owner {
            repo.get_card(&p.tenant_id, owner).await?.into_iter().collect()
        } else {
            repo.legacy_asset_cards(&p.tenant_id, key).await?
        };
        for card in cards {
            if !memoswish_core::content_lifecycle::published(&card)
                && (surface == "feed" || !p.can(Permission::ContentWrite))
            {
                continue;
            }
            if let Some(asset) = card_assets(&card).into_iter().find(|a| a.key == key) {
                reference_owner = Some(card.id.clone());
                reference = Some(asset.clone());
                break;
            }
        }
    }
    let managed = key.starts_with(&format!("{}uploads/", p.asset_prefix()));
    let (spec, version) = if managed {
        let asset = published.as_ref().ok_or_else(missing)?;
        if asset.store_id != store.namespace()? {
            return Err(CoreError::Conflict("asset store namespace mismatch".into()));
        }
        asset.spec.validate()?;
        if reference.is_none() && (surface != "media" || !p.can(Permission::ContentWrite)) {
            return Err(missing());
        }
        if let Some(reference) = &reference {
            validate_asset_ref(reference)?;
            if reference.sha256 != asset.spec.sha256
                || reference.bytes != asset.spec.size as u64
                || reference.mime != asset.spec.mime
            {
                return Err(CoreError::Conflict("asset attachment metadata mismatch".into()));
            }
        }
        (asset.spec.clone(), asset.version.clone())
    } else {
        let reference = reference.as_ref().ok_or_else(missing)?;
        validate_asset_ref(reference)?;
        (
            AssetSpec { mime: reference.mime.clone(), size: reference.bytes as i64, sha256: reference.sha256.clone() },
            ObjectVersion::Unversioned,
        )
    };
    Ok(SelectedDelivery {
        key: key.into(),
        spec,
        version,
        store_id: store.namespace()?,
        publication: published,
        reference,
        reference_owner,
        managed,
    })
}

async fn read_selected(store: &dyn ObjectStore, selected: &SelectedDelivery) -> CoreResult<StoredObject> {
    let object = if selected.managed {
        store.read_delivery(&selected.key, &selected.version, selected.spec.size as u64).await?
    } else {
        store.read_legacy(&selected.key, selected.spec.size as u64).await?
    };
    let mut object = object.ok_or_else(missing)?;
    if object.bytes.len() as i64 != selected.spec.size
        || memoswish_core::ids::sha256_hex(&object.bytes) != selected.spec.sha256
        || (object.mime != selected.spec.mime && !(selected.managed && store.kind() == "local-disk"))
    {
        return Err(CoreError::Conflict("asset integrity verification failed".into()));
    }
    object.mime = selected.spec.mime.clone();
    Ok(object)
}

/// 保留导出及历史调用方的有界全摘要接口。
pub async fn read(
    repo: &dyn Repository,
    store: &dyn ObjectStore,
    p: &Principal,
    key: &str,
    surface: &str,
    owner: Option<&str>,
) -> CoreResult<StoredObject> {
    let selected = select(repo, store, p, key, surface, owner).await?;
    read_selected(store, &selected).await
}

use memoswish_core::asset_read::{BLOCK_BYTES, ObjectReader, ReadManifest};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Duration, Instant, timeout_at};

// 每进程最多 32 个交付缓冲；不建立无界等待队列。
static READERS: std::sync::LazyLock<Arc<Semaphore>> = std::sync::LazyLock::new(|| Arc::new(Semaphore::new(32)));
static LEGACY_READERS: std::sync::LazyLock<Arc<Semaphore>> = std::sync::LazyLock::new(|| Arc::new(Semaphore::new(2)));
pub const DELIVERY_DEADLINE: Duration = Duration::from_secs(60);

pub struct Delivery {
    pub selected: SelectedDelivery,
    pub manifest: Option<ReadManifest>,
    pub buffered: Option<StoredObject>,
    reader: Option<Box<dyn ObjectReader>>,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
    legacy_permit: Option<OwnedSemaphorePermit>,
}

impl Delivery {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// 首块在发头前校验；后续块错误终止正文，绝不发送损坏块。
    pub async fn body(mut self, start: u64, end: u64) -> CoreResult<impl futures::Stream<Item = CoreResult<Vec<u8>>>> {
        if start > end || end >= self.selected.spec.size as u64 {
            return Err(CoreError::invalid("asset response range out of bounds"));
        }
        let deadline = self.deadline;
        let first = self.block(start, end).await?;
        let next = ((start as usize / BLOCK_BYTES + 1) * BLOCK_BYTES) as u64;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        // 独立监督发送期限，即使下游完全停止轮询，也会释放句柄与配额。
        tokio::spawn(async move {
            let mut item = Ok(first);
            let mut offset = next;
            loop {
                let failed = item.is_err();
                if timeout_at(self.deadline, sender.send(item)).await.is_err() || sender.is_closed() || failed {
                    break;
                }
                if offset > end {
                    break;
                }
                item = self.block(offset, end).await;
                offset += BLOCK_BYTES as u64;
            }
        });
        Ok(futures::stream::unfold((Some(receiver), deadline), |(receiver, deadline)| async move {
            let mut receiver = receiver?;
            if Instant::now() >= deadline {
                return Some((Err(CoreError::Unavailable("asset stream deadline exceeded".into())), (None, deadline)));
            }
            match timeout_at(deadline, receiver.recv()).await {
                Ok(Some(item)) => Some((item, (Some(receiver), deadline))),
                Ok(None) => None,
                Err(_) => {
                    Some((Err(CoreError::Unavailable("asset stream deadline exceeded".into())), (None, deadline)))
                }
            }
        }))
    }

    async fn block(&mut self, start: u64, end: u64) -> CoreResult<Vec<u8>> {
        // 所有权一直保留到消费、取消或期限终止；慢消费者恢复轮询也先检查总期限。
        let _ = (&self.permit, &self.legacy_permit);
        if Instant::now() >= self.deadline {
            return Err(CoreError::Unavailable("asset stream deadline exceeded".into()));
        }
        let index = start as usize / BLOCK_BYTES;
        let offset = (index * BLOCK_BYTES) as u64;
        let length = (self.selected.spec.size as u64 - offset).min(BLOCK_BYTES as u64) as usize;
        let bytes = if let Some(reader) = &mut self.reader {
            let bytes = timeout_at(self.deadline, reader.read_at(offset, length))
                .await
                .map_err(|_| CoreError::Unavailable("asset stream deadline exceeded".into()))??;
            self.manifest
                .as_ref()
                .ok_or_else(|| CoreError::internal("asset manifest missing"))?
                .verify_block(index, &bytes)?;
            bytes
        } else {
            self.buffered.as_ref().ok_or_else(|| CoreError::internal("asset buffer missing"))?.bytes
                [offset as usize..offset as usize + length]
                .to_vec()
        };
        let from = (start - offset) as usize;
        let to = ((end - offset + 1).min(length as u64)) as usize;
        Ok(bytes[from..to].to_vec())
    }
}

async fn open_selected(
    store: &dyn ObjectStore,
    selected: &SelectedDelivery,
) -> CoreResult<Option<Box<dyn ObjectReader>>> {
    if selected.managed {
        store.open_delivery(&selected.key, &selected.version, selected.spec.size as u64).await
    } else {
        store.open_legacy(&selected.key, selected.spec.size as u64).await
    }
}

pub async fn open(
    repo: &dyn Repository,
    store: &dyn ObjectStore,
    p: &Principal,
    key: &str,
    surface: &str,
    owner: Option<&str>,
) -> CoreResult<Delivery> {
    let permit = READERS
        .clone()
        .try_acquire_owned()
        .map_err(|_| CoreError::Unavailable("asset reader capacity exhausted".into()))?;
    let deadline = Instant::now() + DELIVERY_DEADLINE;
    timeout_at(deadline, async {
        let selected = select(repo, store, p, key, surface, owner).await?;
        let reader = match open_selected(store, &selected).await {
            Ok(Some(reader)) => Some(reader),
            Ok(None) => return Err(missing()),
            Err(CoreError::Unsupported(_)) => None,
            Err(error) => return Err(error),
        };
        let manifest = repo.asset_read_manifest(&p.tenant_id, key).await?;
        if let (Some(opened), Some(manifest)) = (&reader, &manifest) {
            let expected =
                ReadManifest::new(&selected.store_id, key, &selected.version, opened.metadata(), &selected.spec);
            if opened.metadata().size != selected.spec.size as u64
                || (opened.metadata().mime != selected.spec.mime && !(selected.managed && store.kind() == "local-disk"))
            {
                return Err(CoreError::Conflict("asset read metadata mismatch".into()));
            }
            if opened.metadata().cacheable && manifest.verified && manifest.matches(&expected) {
                return Ok(Delivery {
                    selected,
                    manifest: Some(manifest.clone()),
                    buffered: None,
                    reader,
                    deadline,
                    permit,
                    legacy_permit: None,
                });
            }
        }
        let legacy_permit = LEGACY_READERS
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoreError::Unavailable("legacy reader capacity exhausted".into()))?;
        let buffered = read_selected(store, &selected).await?;
        Ok(Delivery {
            selected,
            manifest: None,
            buffered: Some(buffered),
            reader: None,
            deadline,
            permit,
            legacy_permit: Some(legacy_permit),
        })
    })
    .await
    .map_err(|_| CoreError::Unavailable("asset open deadline exceeded".into()))?
}

/// 显式按对象恢复验证；不启动定时器、工作发现或第二种租约。
pub async fn verify(
    repo: &dyn Repository,
    store: &dyn ObjectStore,
    p: &Principal,
    key: &str,
    surface: &str,
    owner: Option<&str>,
    max_blocks: usize,
) -> CoreResult<ReadManifest> {
    p.require(Permission::MediaWrite)?;
    if !(1..=1024).contains(&max_blocks) {
        return Err(CoreError::invalid("verification block budget must be 1 to 1024"));
    }
    let _permit = READERS
        .clone()
        .try_acquire_owned()
        .map_err(|_| CoreError::Unavailable("asset reader capacity exhausted".into()))?;
    timeout_at(Instant::now() + DELIVERY_DEADLINE, async {
        use sha2::{Digest, Sha256};
        let selected = select(repo, store, p, key, surface, owner).await?;
        let mut reader = open_selected(store, &selected).await?.ok_or_else(missing)?;
        if !reader.metadata().cacheable {
            return Err(CoreError::Unsupported("stable object identity is not qualified on this platform".into()));
        }
        if reader.metadata().size != selected.spec.size as u64
            || (reader.metadata().mime != selected.spec.mime && !(selected.managed && store.kind() == "local-disk"))
        {
            return Err(CoreError::Conflict("asset verification metadata mismatch".into()));
        }
        let expected = ReadManifest::new(&selected.store_id, key, &selected.version, reader.metadata(), &selected.spec);
        let mut manifest =
            repo.asset_read_manifest(&p.tenant_id, key).await?.filter(|m| m.matches(&expected)).unwrap_or(expected);
        if manifest.verified {
            return Ok(manifest);
        }
        let count = (manifest.size as usize).div_ceil(BLOCK_BYTES);
        let stop = (manifest.blocks.len() + max_blocks).min(count);
        for index in manifest.blocks.len()..stop {
            let offset = (index * BLOCK_BYTES) as u64;
            let length = (manifest.size - offset).min(BLOCK_BYTES as u64) as usize;
            manifest.blocks.push(memoswish_core::ids::sha256_hex(&reader.read_at(offset, length).await?));
        }
        if select(repo, store, p, key, surface, owner).await? != selected {
            return Err(CoreError::Conflict("asset reference changed during verification".into()));
        }
        repo.save_asset_read_manifest(&p.tenant_id, key, &manifest).await?;
        if stop == count {
            // 不序列化密码学内部状态；恢复末步重新有界扫描并验证完整摘要。
            let mut full = Sha256::new();
            for index in 0..count {
                let offset = (index * BLOCK_BYTES) as u64;
                let bytes = reader.read_at(offset, (manifest.size - offset).min(BLOCK_BYTES as u64) as usize).await?;
                if manifest.blocks[index] != memoswish_core::ids::sha256_hex(&bytes) {
                    return Err(CoreError::Conflict("asset changed during verification".into()));
                }
                full.update(&bytes);
            }
            if format!("{:x}", full.finalize()) != manifest.sha256 {
                return Err(CoreError::Conflict("asset full digest verification failed".into()));
            }
            if select(repo, store, p, key, surface, owner).await? != selected {
                return Err(CoreError::Conflict("asset reference changed during verification".into()));
            }
            let current = open_selected(store, &selected).await?.ok_or_else(missing)?;
            let current =
                ReadManifest::new(&selected.store_id, key, &selected.version, current.metadata(), &selected.spec);
            if !manifest.matches(&current) {
                return Err(CoreError::Conflict("asset object changed before verification commit".into()));
            }
            manifest.verified = true;
            repo.save_asset_read_manifest(&p.tenant_id, key, &manifest).await?;
        }
        Ok(manifest)
    })
    .await
    .map_err(|_| CoreError::Unavailable("asset verification deadline exceeded".into()))?
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use async_trait::async_trait;
    use memoswish_core::asset_read::ReadIdentity;
    struct Reader(ReadIdentity);
    #[async_trait]
    impl ObjectReader for Reader {
        fn metadata(&self) -> &ReadIdentity {
            &self.0
        }
        async fn read_at(&mut self, _offset: u64, length: usize) -> CoreResult<Vec<u8>> {
            Ok(vec![b'x'; length])
        }
    }
    #[tokio::test(start_paused = true)]
    async fn streaming_stopped_consumer_releases_reader_permit_at_deadline() {
        let capacity = Arc::new(Semaphore::new(1));
        let selected = SelectedDelivery {
            key: "tenants/local/x".into(),
            spec: AssetSpec {
                mime: "image/png".into(),
                size: (3 * BLOCK_BYTES) as i64,
                sha256: memoswish_core::ids::sha256_hex(&vec![b'x'; 3 * BLOCK_BYTES]),
            },
            version: ObjectVersion::Unversioned,
            store_id: "test".into(),
            publication: None,
            reference: None,
            reference_owner: None,
            managed: false,
        };
        let metadata = ReadIdentity {
            cacheable: true,
            identity: "test".into(),
            size: selected.spec.size as u64,
            mime: selected.spec.mime.clone(),
        };
        let mut manifest = ReadManifest::new("test", &selected.key, &selected.version, &metadata, &selected.spec);
        manifest.blocks = vec![memoswish_core::ids::sha256_hex(&vec![b'x'; BLOCK_BYTES]); 3];
        manifest.verified = true;
        let delivery = Delivery {
            selected,
            manifest: Some(manifest),
            buffered: None,
            reader: Some(Box::new(Reader(metadata))),
            deadline: Instant::now() + DELIVERY_DEADLINE,
            permit: capacity.clone().acquire_owned().await.unwrap(),
            legacy_permit: None,
        };
        let body = delivery.body(0, (3 * BLOCK_BYTES - 1) as u64).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(capacity.available_permits(), 0);
        tokio::time::advance(DELIVERY_DEADLINE + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(capacity.available_permits(), 1, "unpolled body must not retain a reader past its deadline");
        use futures::StreamExt;
        let remaining: Vec<_> = body.collect().await;
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].is_err(), "queued bytes must not be emitted after the deadline");
    }
}
