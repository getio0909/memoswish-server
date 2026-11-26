//! 本地磁盘对象存储：对象写入 `<root>/<key>`，通过 `GET /assets/<key>` 对外提供。

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use memoswish_core::ids::sha256_hex;
use memoswish_core::store::{ObjectStore, StoredObject, validate_key};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::AssetRef;

/// 本地磁盘存储。
#[derive(Debug, Clone)]
pub struct LocalDiskStore {
    root: PathBuf,
    url_prefix: String,
}

impl LocalDiskStore {
    /// `root` 为存储根目录，`url_prefix` 通常为 `/assets`。
    pub fn new(root: impl Into<PathBuf>, url_prefix: impl Into<String>) -> Self {
        Self { root: root.into(), url_prefix: url_prefix.into().trim_end_matches('/').to_string() }
    }

    fn path_for(&self, key: &str) -> CoreResult<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(key))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// 根据扩展名推断 MIME。
pub fn mime_from_key(key: &str) -> &'static str {
    match key.rsplit('.').next().unwrap_or_default() {
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "m4a" => "audio/mp4",
        "gif" => "image/gif",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

async fn persist_object(tmp: &Path, path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let (tmp, path, bytes) = (tmp.to_owned(), path.to_owned(), bytes.to_owned());
    // 一个阻塞任务拥有写入、重命名与临时文件清理，等待方取消也不会拆开这些步骤。
    tokio::task::spawn_blocking(move || {
        let _cleanup = TemporaryObject(tmp.clone());
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    })
    .await
    .map_err(CoreError::internal)?
    .map_err(CoreError::internal)
}

struct TemporaryObject(PathBuf);

impl Drop for TemporaryObject {
    fn drop(&mut self) {
        if let Err(cleanup) = std::fs::remove_file(&self.0)
            && cleanup.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(target: "memoswish::storage::local_disk", path = %self.0.display(), %cleanup, "Failed to remove temporary object after PUT");
        }
    }
}

#[async_trait]
impl ObjectStore for LocalDiskStore {
    fn kind(&self) -> &'static str {
        "local-disk"
    }

    async fn open_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        size: u64,
    ) -> CoreResult<Option<Box<dyn memoswish_core::asset_read::ObjectReader>>> {
        validate_key(key)?;
        if version != &memoswish_core::assets::ObjectVersion::Unversioned || size > 64 * 1024 * 1024 {
            return Err(CoreError::Unsupported("unsupported local read identity".into()));
        }
        let root = self.root.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let dir =
                cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority()).map_err(CoreError::internal)?;
            let mut options = cap_std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                // 非阻塞打开后再检查类型，FIFO 和设备不能占住异步工作者。
                options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
            }
            let file = match dir.open_with(&key, &options) {
                Ok(file) => file.into_std(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(CoreError::Forbidden("object is not a confined regular file".into())),
            };
            let metadata = file.metadata().map_err(CoreError::internal)?;
            if !metadata.is_file() || metadata.len() > size {
                return Err(CoreError::Conflict("asset file identity mismatch".into()));
            }
            let identity = file_identity(&metadata)?;
            let metadata = memoswish_core::asset_read::ReadIdentity {
                cacheable: cfg!(unix),
                identity,
                size: metadata.len(),
                mime: mime_from_key(&key).into(),
            };
            let reader = LocalReader { file: tokio::fs::File::from_std(file), metadata };
            Ok(Some(Box::new(reader) as Box<dyn memoswish_core::asset_read::ObjectReader>))
        })
        .await
        .map_err(CoreError::internal)?
    }

    fn namespace(&self) -> CoreResult<String> {
        use std::io::{Read, Write};
        std::fs::create_dir_all(&self.root).map_err(CoreError::internal)?;
        let root = std::fs::canonicalize(&self.root).map_err(CoreError::internal)?;
        let marker = root.join(".learntok-store-id");
        if !marker.try_exists().map_err(CoreError::internal)? {
            // 首次值兼容旧路径摘要；以后随备份携带，不因冷恢复目录改变而漂移。
            let identity = format!("local_{}", sha256_hex(root.as_os_str().as_encoded_bytes()));
            let temporary = root.join(format!(".learntok-store-id-{}", memoswish_core::ids::new_id()));
            let _cleanup = TemporaryObject(temporary.clone());
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(CoreError::internal)?;
            file.write_all(identity.as_bytes()).map_err(CoreError::internal)?;
            file.sync_all().map_err(CoreError::internal)?;
            match std::fs::hard_link(&temporary, &marker) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(CoreError::internal(e)),
            }
        }
        let meta = std::fs::symlink_metadata(&marker).map_err(CoreError::internal)?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(CoreError::invalid("invalid local store namespace marker"));
        }
        let mut identity = String::new();
        std::fs::File::open(marker)
            .map_err(CoreError::internal)?
            .take(129)
            .read_to_string(&mut identity)
            .map_err(|_| CoreError::invalid("invalid local store namespace marker"))?;
        memoswish_core::assets::validate_asset_id(&identity)?;
        if !identity.starts_with("local_") {
            return Err(CoreError::invalid("invalid local store namespace marker"));
        }
        Ok(identity)
    }

    async fn read_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        limit: u64,
    ) -> CoreResult<Option<StoredObject>> {
        let Some(mut reader) = self.open_delivery(key, version, limit).await? else { return Ok(None) };
        let size = reader.metadata().size;
        let mime = reader.metadata().mime.clone();
        let mut bytes = Vec::with_capacity(size as usize);
        while (bytes.len() as u64) < size {
            let offset = bytes.len() as u64;
            bytes.extend_from_slice(
                &reader
                    .read_at(offset, (size - offset).min(memoswish_core::asset_read::BLOCK_BYTES as u64) as usize)
                    .await?,
            );
        }
        Ok(Some(StoredObject { bytes, mime }))
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        let path = self.path_for(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(CoreError::internal)?;
        }
        let sha = sha256_hex(&bytes);
        let len = bytes.len() as u64;
        // 先写临时文件再原子重命名，避免客户端读到半个文件。
        // 每次 PUT 使用独立名字，失败清理不会删除并发写入者的临时文件。
        let tmp = path.with_extension(format!("tmp-{}", memoswish_core::ids::new_id()));
        persist_object(&tmp, &path, &bytes).await?;
        Ok(AssetRef { key: key.to_string(), url: self.url_for(key), mime: mime.to_string(), bytes: len, sha256: sha })
    }

    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        let path = self.path_for(key)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(StoredObject { bytes, mime: mime_from_key(key).to_string() })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CoreError::internal(e)),
        }
    }

    async fn exists(&self, key: &str) -> CoreResult<bool> {
        Ok(tokio::fs::try_exists(self.path_for(key)?).await.unwrap_or(false))
    }

    async fn delete(&self, key: &str) -> CoreResult<()> {
        match tokio::fs::remove_file(self.path_for(key)?).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CoreError::internal(e)),
        }
    }

    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        let root = self.path_for(prefix.trim_end_matches('/'))?;
        let mut pending = vec![root];
        let mut keys = Vec::new();
        while let Some(dir) = pending.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(CoreError::internal(e)),
            };
            while let Some(e) = entries.next_entry().await.map_err(CoreError::internal)? {
                let typ = e.file_type().await.map_err(CoreError::internal)?;
                if typ.is_symlink() {
                    return Err(CoreError::internal("symlink in object store"));
                }
                if typ.is_dir() {
                    pending.push(e.path());
                } else if typ.is_file() {
                    keys.push(
                        e.path()
                            .strip_prefix(&self.root)
                            .map_err(CoreError::internal)?
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        keys.sort();
        Ok(keys)
    }

    async fn purge_prefix(&self, prefix: &str) -> CoreResult<()> {
        // 临时文件同样位于租户前缀内；不能只清扫成功重命名后的对象。
        // 直接处理磁盘路径，避免临时扩展名令合法对象键超过长度上限而无法删除。
        for key in self.list_prefix(prefix).await? {
            match tokio::fs::remove_file(self.root.join(key)).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(CoreError::internal(e)),
            }
        }
        Ok(())
    }

    fn url_for(&self, key: &str) -> String {
        format!("{}/{}", self.url_prefix, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_write_removes_temporary_file_and_preserves_destination() {
        let dir = std::env::temp_dir().join(format!("memoswish-store-{}", memoswish_core::ids::new_id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let destination = dir.join("image.png");
        let tmp = dir.join("image.tmp-test");
        tokio::fs::write(&destination, b"original").await.unwrap();
        // 用设备的 ENOSPC 确定性模拟写入失败，只移除测试目录里的链接。
        std::os::unix::fs::symlink("/dev/full", &tmp).unwrap();
        let error = persist_object(&tmp, &destination, b"partial image").await.unwrap_err();
        assert!(error.to_string().contains("No space left on device"), "{error}");
        assert!(tokio::fs::symlink_metadata(&tmp).await.is_err());
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"original");
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn failed_put_removes_temporary_file_and_preserves_destination() {
        let dir = std::env::temp_dir().join(format!("memoswish-store-{}", memoswish_core::ids::new_id()));
        let store = LocalDiskStore::new(&dir, "/assets");
        let key = "tenants/t1/imports/image.png";
        let destination = dir.join(key);
        tokio::fs::create_dir_all(&destination).await.unwrap();
        tokio::fs::write(destination.join("keep"), b"original").await.unwrap();
        for _ in 0..3 {
            assert!(store.put(key, b"partial image".to_vec(), "image/png").await.is_err());
            let mut entries = tokio::fs::read_dir(destination.parent().unwrap()).await.unwrap();
            assert_eq!(entries.next_entry().await.unwrap().unwrap().path(), destination);
            assert!(entries.next_entry().await.unwrap().is_none());
            assert_eq!(tokio::fs::read(destination.join("keep")).await.unwrap(), b"original");
        }
        tokio::fs::remove_dir_all(&destination).await.unwrap();
        let (first, second) = tokio::join!(
            store.put(key, b"image".to_vec(), "image/png"),
            store.put(key, b"image".to_vec(), "image/png"),
        );
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(store.get(key).await.unwrap().unwrap().bytes, b"image");
        let mut entries = tokio::fs::read_dir(destination.parent().unwrap()).await.unwrap();
        assert_eq!(entries.next_entry().await.unwrap().unwrap().path(), destination);
        assert!(entries.next_entry().await.unwrap().is_none());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn purge_removes_stray_temporary_files_even_beyond_object_key_limit() {
        let dir = std::env::temp_dir().join(format!("memoswish-store-{}", memoswish_core::ids::new_id()));
        let store = LocalDiskStore::new(&dir, "/assets");
        let prefix = format!("tenants/{}/{}/", "a".repeat(200), "b".repeat(200));
        let key = format!("{prefix}{}.png", "c".repeat(95));
        validate_key(&key).unwrap();
        store.put(&key, b"object".to_vec(), "image/png").await.unwrap();
        let tmp = dir.join(&key).with_extension(format!("tmp-{}", memoswish_core::ids::new_id()));
        assert!(tmp.strip_prefix(&dir).unwrap().to_str().unwrap().len() > 512);
        tokio::fs::write(&tmp, b"private unfinished write").await.unwrap();
        store.put("tenants/other/keep.png", b"keep".to_vec(), "image/png").await.unwrap();
        store.purge_prefix(&prefix).await.unwrap();
        assert!(store.list_prefix(&prefix).await.unwrap().is_empty());
        assert!(!tmp.exists());
        assert!(store.exists("tenants/other/keep.png").await.unwrap());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[test]
    fn cancelled_queued_write_still_cleans_temporary_file_on_rename_failure() {
        let dir = std::env::temp_dir().join(format!("memoswish-store-{}", memoswish_core::ids::new_id()));
        let destination = dir.join("image.png");
        let tmp = dir.join("image.tmp-delayed");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(destination.join("keep"), b"original").unwrap();
        let runtime =
            tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(1).build().unwrap();
        runtime.block_on(async {
            let entered = std::sync::Arc::new(tokio::sync::Notify::new());
            let (release, receive) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking({
                let entered = entered.clone();
                move || {
                    entered.notify_one();
                    receive.recv().unwrap();
                }
            });
            entered.notified().await;
            let writer = tokio::spawn({
                let (tmp, destination) = (tmp.clone(), destination.clone());
                async move { persist_object(&tmp, &destination, b"private partial bytes").await }
            });
            // 唯一的阻塞线程仍被占用，写入已入队但尚未创建临时文件。
            tokio::task::yield_now().await;
            assert!(!tmp.exists());
            writer.abort();
            assert!(writer.await.unwrap_err().is_cancelled());
            release.send(()).unwrap();
            blocker.await.unwrap();
        });
        // 等待已入队的阻塞任务全部退出后，才检查取消后的实际文件系统。
        runtime.shutdown_timeout(std::time::Duration::from_secs(5));
        assert!(!tmp.exists());
        assert_eq!(std::fs::read(destination.join("keep")).unwrap(), b"original");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn put_get_delete() {
        let dir = std::env::temp_dir().join(format!("memoswish-store-{}", memoswish_core::ids::new_id()));
        let store = LocalDiskStore::new(&dir, "/assets/");
        let r = store.put("tenants/t1/tts/a.wav", b"RIFF".to_vec(), "audio/wav").await.unwrap();
        assert_eq!(r.url, "/assets/tenants/t1/tts/a.wav");
        assert_eq!(r.bytes, 4);
        assert!(store.exists("tenants/t1/tts/a.wav").await.unwrap());
        assert_eq!(store.get("tenants/t1/tts/a.wav").await.unwrap().unwrap().bytes, b"RIFF");
        assert!(store.get("../escape").await.is_err());
        store.put("tenants/t1/imports/test.gif", b"GIF89a".to_vec(), "image/gif").await.unwrap();
        assert_eq!(store.get("tenants/t1/imports/test.gif").await.unwrap().unwrap().mime, "image/gif");
        store.delete("tenants/t1/tts/a.wav").await.unwrap();
        assert!(store.get("tenants/t1/tts/a.wav").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod namespace_regressions {
    use super::*;
    #[tokio::test]
    async fn copied_store_keeps_namespace_but_unrelated_roots_and_invalid_markers_do_not() {
        let root = std::env::temp_dir().join(format!("s16-namespace-{}", memoswish_core::ids::new_id()));
        let original = root.join("original");
        let restored = root.join("restored");
        let unrelated = root.join("unrelated");
        for p in [&original, &restored, &unrelated] {
            std::fs::create_dir_all(p).unwrap();
        }
        let a = LocalDiskStore::new(&original, "/assets");
        let b = LocalDiskStore::new(&restored, "/assets");
        let c = LocalDiskStore::new(&unrelated, "/assets");
        let identity = a.namespace().unwrap();
        assert_eq!(a.namespace().unwrap(), identity);
        std::fs::copy(original.join(".learntok-store-id"), restored.join(".learntok-store-id")).unwrap();
        assert_eq!(b.namespace().unwrap(), identity);
        assert_ne!(c.namespace().unwrap(), identity);
        std::fs::write(restored.join(".learntok-store-id"), b"https://SECRET_SENTINEL.invalid").unwrap();
        let err = b.namespace().unwrap_err();
        assert!(!format!("{err:?}").contains("SECRET_SENTINEL"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

// inode 与变更时间绑定已打开句柄；其他平台未证明等价身份时保留旧校验路径。
fn file_identity(metadata: &std::fs::Metadata) -> CoreResult<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(sha256_hex(
            format!(
                "{}:{}:{}:{}:{}:{}:{}",
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec()
            )
            .as_bytes(),
        ))
    }
    #[cfg(not(unix))]
    {
        Ok(sha256_hex(format!("{}:{:?}:{:?}", metadata.len(), metadata.modified(), metadata.created()).as_bytes()))
    }
}

struct LocalReader {
    file: tokio::fs::File,
    metadata: memoswish_core::asset_read::ReadIdentity,
}

#[async_trait]
impl memoswish_core::asset_read::ObjectReader for LocalReader {
    fn metadata(&self) -> &memoswish_core::asset_read::ReadIdentity {
        &self.metadata
    }
    async fn read_at(&mut self, offset: u64, length: usize) -> CoreResult<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        if length > memoswish_core::asset_read::BLOCK_BYTES
            || offset.checked_add(length as u64).is_none_or(|end| end > self.metadata.size)
        {
            return Err(CoreError::invalid("asset read exceeds block bounds"));
        }
        if file_identity(&self.file.metadata().await.map_err(CoreError::internal)?)? != self.metadata.identity {
            return Err(CoreError::Conflict("asset changed during read".into()));
        }
        self.file.seek(std::io::SeekFrom::Start(offset)).await.map_err(CoreError::internal)?;
        let mut bytes = vec![0; length];
        self.file
            .read_exact(&mut bytes)
            .await
            .map_err(|_| CoreError::Conflict("asset truncated during read".into()))?;
        if file_identity(&self.file.metadata().await.map_err(CoreError::internal)?)? != self.metadata.identity {
            return Err(CoreError::Conflict("asset changed during read".into()));
        }
        Ok(bytes)
    }
}

#[cfg(all(test, unix))]
mod confined_read_tests {
    use super::*;
    use memoswish_core::assets::ObjectVersion;
    #[tokio::test]
    async fn streaming_confines_symlinks_refuses_fifo_and_detects_mutation() {
        let root = std::env::temp_dir().join(format!("p39-confined-{}", memoswish_core::ids::new_id()));
        let outside = root.with_extension("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"abc").unwrap();
        let store = LocalDiskStore::new(&root, "/assets");
        std::os::unix::fs::symlink(outside.join("secret"), root.join("file-link")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("parent-link")).unwrap();
        for key in ["file-link", "parent-link/secret"] {
            assert!(store.open_delivery(key, &ObjectVersion::Unversioned, 3).await.is_err());
            assert!(store.read_delivery(key, &ObjectVersion::Unversioned, 3).await.is_err());
        }
        assert!(std::process::Command::new("mkfifo").arg(root.join("pipe")).status().unwrap().success());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                store.open_delivery("pipe", &ObjectVersion::Unversioned, 3)
            )
            .await
            .unwrap()
            .is_err()
        );
        store.put("regular", b"abc".to_vec(), "image/png").await.unwrap();
        let mut reader = store.open_delivery("regular", &ObjectVersion::Unversioned, 3).await.unwrap().unwrap();
        std::fs::write(root.join("regular"), b"bad!").unwrap();
        assert!(reader.read_at(0, 3).await.is_err());
        assert!(reader.read_at(0, memoswish_core::asset_read::BLOCK_BYTES + 1).await.is_err());
        assert!(reader.read_at(u64::MAX, 1).await.is_err());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
