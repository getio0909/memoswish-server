//! 对象存储抽象（默认本地磁盘，商业版 S3 兼容存储）。

use async_trait::async_trait;
use memoswish_protocol::AssetRef;

use crate::error::{CoreError, CoreResult};

/// 读取到的对象。
#[derive(Debug, Clone)]
pub struct StoredObject {
    pub bytes: Vec<u8>,
    pub mime: String,
}

/// 一次 PUT 的精确清理回执；版本化存储必须返回版本 ID。
pub struct ObjectWrite {
    pub asset: AssetRef,
    pub version: Option<String>,
}

/// 二进制资产存储。
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// 存储实现标识，例如 `local-disk`、`s3`。
    fn kind(&self) -> &'static str;
    /// 物理存储稳定绑定；未实现时禁止持久资产交付。
    fn namespace(&self) -> CoreResult<String> {
        Err(CoreError::Unsupported("object store namespace is unavailable".into()))
    }
    /// 元数据打开不消费正文；只有通过可信块清单验证后才能交付区间。
    async fn open_delivery(
        &self,
        _key: &str,
        _version: &crate::assets::ObjectVersion,
        _size: u64,
    ) -> CoreResult<Option<Box<dyn crate::asset_read::ObjectReader>>> {
        Err(CoreError::Unsupported("streaming object reads are unavailable".into()))
    }
    /// 历史引用选择当前对象，但句柄之后必须固定同一身份。
    async fn open_legacy(&self, key: &str, size: u64) -> CoreResult<Option<Box<dyn crate::asset_read::ObjectReader>>> {
        self.open_delivery(key, &crate::assets::ObjectVersion::Unversioned, size).await
    }
    /// 有界精确读取；不能将未知或不支持的版本降级为 latest。
    async fn read_delivery(
        &self,
        _key: &str,
        _version: &crate::assets::ObjectVersion,
        _limit: u64,
    ) -> CoreResult<Option<StoredObject>> {
        Err(CoreError::Unsupported("bounded versioned object reads are unavailable".into()))
    }
    /// legacy 没有历史版本证据，只能按业务引用摘要验证当前字节。
    async fn read_legacy(&self, key: &str, limit: u64) -> CoreResult<Option<StoredObject>> {
        self.read_delivery(key, &crate::assets::ObjectVersion::Unversioned, limit).await
    }
    /// 写入对象并返回引用（URL 由 `url_for` 生成）。
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef>;
    /// 原子创建共享引导标识；存在时返回 false，禁止以读后写模拟条件创建。
    async fn put_if_absent(&self, _key: &str, _bytes: Vec<u8>, _mime: &str) -> CoreResult<bool> {
        Err(CoreError::Unsupported("conditional object creation is unavailable".into()))
    }
    /// 默认适用于无版本存储；版本化实现必须覆写写入和补偿方法。
    async fn put_versioned(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<ObjectWrite> {
        Ok(ObjectWrite { asset: self.put(key, bytes, mime).await?, version: None })
    }
    /// 删除本次写入；版本化实现不能用普通 DELETE 创建删除标记。
    async fn delete_write(&self, key: &str, _version: Option<&str>) -> CoreResult<()> {
        self.delete(key).await
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>>;
    async fn exists(&self, key: &str) -> CoreResult<bool>;
    async fn delete(&self, key: &str) -> CoreResult<()>;
    /// 列举完整前缀下的对象键；不支持列举时显式报错，禁止误报擦除完成。
    async fn list_prefix(&self, _prefix: &str) -> CoreResult<Vec<String>> {
        Err(CoreError::Unsupported("object enumeration is unavailable".into()))
    }
    /// 擦除目录下全部对象；版本化实现还必须删除历史版本和删除标记。
    async fn purge_prefix(&self, prefix: &str) -> CoreResult<()> {
        for key in self.list_prefix(prefix).await? {
            self.delete(&key).await?;
        }
        Ok(())
    }
    /// 生成客户端可访问的 URL（本地存储为 `/assets/<key>`，S3 为预签名 URL）。
    fn url_for(&self, key: &str) -> String;
}

/// 校验对象键：只允许 `[A-Za-z0-9._/-]`，禁止 `..`、绝对路径与空段，防止路径穿越。
pub fn validate_key(key: &str) -> CoreResult<()> {
    let ok = !key.is_empty()
        && key.len() <= 512
        && !key.starts_with('/')
        && !key.ends_with('/')
        && key.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
    if ok { Ok(()) } else { Err(CoreError::invalid(format!("invalid object key `{key}`"))) }
}

#[cfg(test)]
mod tests {
    use super::validate_key;

    #[test]
    fn key_validation() {
        assert!(validate_key("tenants/local/tts/abc.wav").is_ok());
        assert!(validate_key("../etc/passwd").is_err());
        assert!(validate_key("/abs").is_err());
        assert!(validate_key("a//b").is_err());
        assert!(validate_key("a/./b").is_err());
        assert!(validate_key("a b").is_err());
    }
}
