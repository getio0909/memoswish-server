//! 可信块清单只提供完整性证据，不能替代当前引用与凭据授权。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::assets::{AssetSpec, ObjectVersion};
use crate::{CoreError, CoreResult};

pub const BLOCK_BYTES: usize = 64 * 1024;
pub const MAX_BLOCKS: usize = 1024;

/// 打开句柄的元数据；identity 绑定版本或已打开的本地文件身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadIdentity {
    pub cacheable: bool,
    pub identity: String,
    pub size: u64,
    pub mime: String,
}

/// 每次最多读一个校验块；实现必须拒绝截断、超长与身份变化。
#[async_trait]
pub trait ObjectReader: Send + Sync {
    fn metadata(&self) -> &ReadIdentity;
    async fn read_at(&mut self, offset: u64, length: usize) -> CoreResult<Vec<u8>>;
}

/// 未完成记录用于显式恢复验证，只有完整摘要核验后 verified 才可为真。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadManifest {
    pub binding: String,
    pub sha256: String,
    pub size: u64,
    pub mime: String,
    pub blocks: Vec<String>,
    pub verified: bool,
}

impl ReadManifest {
    pub fn new(store: &str, key: &str, version: &ObjectVersion, identity: &ReadIdentity, spec: &AssetSpec) -> Self {
        let binding = crate::ids::sha256_hex(format!("{store}\0{key}\0{version:?}\0{}", identity.identity).as_bytes());
        Self {
            binding,
            sha256: spec.sha256.clone(),
            size: spec.size as u64,
            mime: spec.mime.clone(),
            blocks: vec![],
            verified: false,
        }
    }

    pub fn validate(&self) -> CoreResult<()> {
        AssetSpec {
            mime: self.mime.clone(),
            size: i64::try_from(self.size).unwrap_or(-1),
            sha256: self.sha256.clone(),
        }
        .validate()?;
        let hash = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let count = (self.size as usize).div_ceil(BLOCK_BYTES);
        if !hash(&self.binding)
            || self.blocks.len() > count
            || self.blocks.len() > MAX_BLOCKS
            || self.blocks.iter().any(|h| !hash(h))
            || (self.verified && self.blocks.len() != count)
        {
            return Err(CoreError::invalid("invalid asset read manifest"));
        }
        Ok(())
    }

    pub fn matches(&self, expected: &Self) -> bool {
        self.binding == expected.binding
            && self.sha256 == expected.sha256
            && self.size == expected.size
            && self.mime == expected.mime
    }

    pub fn verify_block(&self, index: usize, bytes: &[u8]) -> CoreResult<()> {
        let offset = index
            .checked_mul(BLOCK_BYTES)
            .and_then(|value| u64::try_from(value).ok())
            .filter(|offset| *offset < self.size)
            .ok_or_else(|| CoreError::invalid("asset block index out of bounds"))?;
        let expected_len = (self.size - offset).min(BLOCK_BYTES as u64) as usize;
        if !self.verified
            || bytes.len() != expected_len
            || self.blocks.get(index) != Some(&crate::ids::sha256_hex(bytes))
        {
            return Err(CoreError::Conflict("asset block integrity verification failed".into()));
        }
        Ok(())
    }
}

/// 发布端已有完整字节，不再次读取对象正文；不支持新端口的旧适配器安全退回旧路径。
pub async fn register_write(
    repo: &dyn crate::repo::Repository,
    store: &dyn crate::store::ObjectStore,
    tenant: &str,
    key: &str,
    version: &ObjectVersion,
    spec: &AssetSpec,
    bytes: &[u8],
) -> CoreResult<()> {
    spec.validate()?;
    if bytes.len() as i64 != spec.size || crate::ids::sha256_hex(bytes) != spec.sha256 {
        return Err(CoreError::invalid("asset bytes do not match publication"));
    }
    let blocks = bytes.chunks(BLOCK_BYTES).map(crate::ids::sha256_hex).collect();
    register_blocks(repo, store, tenant, key, version, spec, blocks).await
}

/// 调用者先验证完整摘要，随后将同一组字节的块摘要绑定写入回执。
pub async fn register_blocks(
    repo: &dyn crate::repo::Repository,
    store: &dyn crate::store::ObjectStore,
    tenant: &str,
    key: &str,
    version: &ObjectVersion,
    spec: &AssetSpec,
    blocks: Vec<String>,
) -> CoreResult<()> {
    let reader = match store.open_delivery(key, version, spec.size as u64).await {
        Ok(Some(reader)) => reader,
        Err(CoreError::Unsupported(_)) => return Ok(()),
        Ok(None) => return Err(CoreError::NotFound("asset".into())),
        Err(error) => return Err(error),
    };
    if !reader.metadata().cacheable {
        return Ok(());
    }
    let mut manifest = ReadManifest::new(&store.namespace()?, key, version, reader.metadata(), spec);
    manifest.blocks = blocks;
    manifest.verified = true;
    repo.save_asset_read_manifest(tenant, key, &manifest).await
}
