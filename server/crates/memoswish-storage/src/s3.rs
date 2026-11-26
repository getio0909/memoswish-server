//! S3 兼容对象存储：基于 AWS Signature V4（路径风格）支持 AWS S3、MinIO、Cloudflare R2 等端点。

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use memoswish_core::ids::sha256_hex;
use memoswish_core::store::{ObjectStore, StoredObject, validate_key};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::AssetRef;
use reqwest::Method;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::local_disk::mime_from_key;

pub use crate::s3_config::S3Config;

/// S3 兼容对象存储客户端。
#[derive(Debug, Clone)]
pub struct S3Store {
    pub config: S3Config,
    client: reqwest::Client,
}

impl S3Store {
    /// 校验配置并创建 S3 存储客户端。
    pub fn new(config: S3Config) -> CoreResult<Self> {
        if config.endpoint.trim().is_empty() {
            return Err(CoreError::invalid("s3 endpoint must not be empty"));
        }
        validate_bucket(&config.bucket)?;
        if config.region.trim().is_empty() {
            return Err(CoreError::invalid("s3 region must not be empty"));
        }
        for value in std::iter::once(&config.endpoint).chain(config.public_base_url.iter()) {
            let url = reqwest::Url::parse(value).map_err(|_| CoreError::invalid("invalid s3 URL"))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(CoreError::invalid("s3 URL must be HTTP(S) without credentials, query or fragment"));
            }
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| CoreError::internal("S3 response processing failed"))?;
        Ok(Self { config, client })
    }

    /// 使用默认 HTTP 客户端直接从配置构造（适合测试或已校验配置）。
    pub fn from_config(config: S3Config) -> Self {
        Self::new(config).expect("valid S3 test configuration")
    }

    async fn read_bounded(
        &self,
        key: &str,
        query: &str,
        expected: Option<&str>,
        limit: u64,
    ) -> CoreResult<Option<StoredObject>> {
        validate_key(key)?;
        let mut response = self.send_signed_query(Method::GET, key, Vec::new(), None, query).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(CoreError::internal("S3 asset read failed"));
        }
        let actual_version = response.headers().get("x-amz-version-id").and_then(|v| v.to_str().ok());
        if let Some(expected) = expected
            && actual_version != Some(expected)
            && !(expected == "null" && actual_version.is_none())
        {
            return Err(CoreError::Conflict("S3 object version mismatch".into()));
        }
        if response.content_length().is_some_and(|len| len > limit) {
            return Err(CoreError::invalid("asset exceeds delivery size limit"));
        }
        let mime = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| mime_from_key(key))
            .to_string();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| CoreError::internal("S3 asset body read failed"))? {
            if chunk.len() as u64 > limit.saturating_sub(bytes.len() as u64) {
                return Err(CoreError::invalid("asset exceeds delivery size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Some(StoredObject { bytes, mime }))
    }

    /// 生成对象的路径风格完整 URL、规范化路径与 Host 头。
    fn resolve_target(&self, key: &str) -> CoreResult<(String, String, String)> {
        validate_bucket(&self.config.bucket)?;
        if !key.is_empty() {
            validate_key(key)?;
        }
        let endpoint =
            reqwest::Url::parse(&self.config.endpoint).map_err(|_| CoreError::invalid("invalid S3 endpoint"))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(CoreError::invalid("invalid S3 endpoint"));
        }
        let full_url =
            format!("{}/{}/{}", self.config.endpoint.trim_end_matches('/'), self.config.bucket, encode_path(key));
        let parsed = reqwest::Url::parse(&full_url).map_err(|_| CoreError::invalid("invalid S3 target"))?;
        if parsed.origin() != endpoint.origin() {
            return Err(CoreError::invalid("S3 target changed origin"));
        }
        let host = match parsed.port() {
            Some(port) => format!("{}:{port}", parsed.host_str().unwrap()),
            None => parsed.host_str().unwrap().to_owned(),
        };
        Ok((full_url, parsed.path().to_owned(), host.to_owned()))
    }

    /// 发送经过 AWS Signature V4 签名的 HTTP 请求。
    async fn send_signed(
        &self,
        method: Method,
        key: &str,
        payload: Vec<u8>,
        content_type: Option<&str>,
    ) -> CoreResult<reqwest::Response> {
        validate_key(key)?;
        self.send_signed_query(method, key, payload, content_type, "").await
    }

    async fn send_signed_query(
        &self,
        method: Method,
        key: &str,
        payload: Vec<u8>,
        content_type: Option<&str>,
        query: &str,
    ) -> CoreResult<reqwest::Response> {
        self.send_request(method, key, payload, content_type, (query, false), &[]).await
    }

    async fn send_request(
        &self,
        method: Method,
        key: &str,
        payload: Vec<u8>,
        content_type: Option<&str>,
        query_condition: (&str, bool),
        extra_headers: &[(&str, &str)],
    ) -> CoreResult<reqwest::Response> {
        let (query, create_only) = query_condition;
        let (target, _, _) = self.resolve_target(key)?;
        let payload_hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&payload));
        let mut headers = extra_headers.to_vec();
        if create_only {
            headers.push(("if-none-match", "*"));
        }
        if method == Method::PUT {
            headers.push(("x-amz-checksum-sha256", payload_hash.as_str()));
        }
        headers.sort_unstable_by_key(|(name, _)| *name);
        let params: Vec<_> = reqwest::Url::parse(&format!("http://localhost/?{query}"))
            .map_err(|_| CoreError::invalid("invalid S3 query"))?
            .query_pairs()
            .into_owned()
            .collect();
        let method_signer = match method {
            Method::GET => rusty_s3::Method::Get,
            Method::HEAD => rusty_s3::Method::Head,
            Method::PUT => rusty_s3::Method::Put,
            Method::DELETE => rusty_s3::Method::Delete,
            _ => return Err(CoreError::invalid("unsupported S3 method")),
        };
        let now = jiff::Timestamp::from_second(Utc::now().timestamp())
            .map_err(|_| CoreError::internal("invalid signing time"))?;
        let signed = rusty_s3::signing::sign(
            &now,
            method_signer,
            reqwest::Url::parse(&target).map_err(|_| CoreError::invalid("invalid S3 target"))?,
            &self.config.access_key_id,
            &self.config.secret_access_key,
            None,
            &self.config.region,
            60,
            params.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            headers.iter().copied(),
        );
        // 查询签名绑定摘要头；不输出 URL，传输错误也不保留含签名的 reqwest source。
        let mut req = self.client.request(method, signed);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        if let Some(ct) = content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, ct);
        }
        req.body(payload).send().await.map_err(|_| CoreError::Unavailable("S3 request failed".into()))
    }

    /// 生成指定有效期的预签名 GET URL。
    pub fn presign_get_url(&self, key: &str, expires_secs: u64) -> String {
        self.presign_get_url_at(key, expires_secs, Utc::now())
    }

    /// 在给定时间点生成预签名 GET URL（便于确定性测试）。
    pub fn presign_get_url_at(&self, key: &str, expires_secs: u64, now: DateTime<Utc>) -> String {
        let Ok((url, _, _)) = self.resolve_target(key) else { return String::new() };
        let Ok(date) = jiff::Timestamp::from_second(now.timestamp()) else { return String::new() };
        let Ok(url) = reqwest::Url::parse(&url) else { return String::new() };
        rusty_s3::signing::sign(
            &date,
            rusty_s3::Method::Get,
            url,
            &self.config.access_key_id,
            &self.config.secret_access_key,
            None,
            &self.config.region,
            expires_secs.clamp(1, 604_800),
            std::iter::empty(),
            std::iter::empty(),
        )
        .to_string()
    }
}

fn validate_bucket(bucket: &str) -> CoreResult<()> {
    if !(3..=63).contains(&bucket.len())
        || bucket.starts_with('.')
        || bucket.ends_with('.')
        || !bucket.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        return Err(CoreError::invalid("invalid S3 bucket name"));
    }
    Ok(())
}

/// 按 RFC 3986 进行百分号编码。
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved || (!encode_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 对对象键路径进行 URI 编码（保留 `/` 分隔符）。
fn encode_path(key: &str) -> String {
    uri_encode(key, false)
}

#[async_trait]
impl ObjectStore for S3Store {
    fn kind(&self) -> &'static str {
        "s3"
    }

    fn namespace(&self) -> CoreResult<String> {
        Ok(format!(
            "s3_{}",
            sha256_hex(format!("{}/{}", self.config.endpoint.trim_end_matches('/'), self.config.bucket).as_bytes())
        ))
    }

    async fn open_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        size: u64,
    ) -> CoreResult<Option<Box<dyn memoswish_core::asset_read::ObjectReader>>> {
        use memoswish_core::assets::ObjectVersion;
        version.validate()?;
        let version = match version {
            ObjectVersion::Unknown => return Err(CoreError::Conflict("object version is unknown".into())),
            ObjectVersion::Unversioned => "null",
            ObjectVersion::VersionId(id) => id,
        };
        self.open_snapshot(key, &format!("versionId={}", uri_encode(version, true)), Some(version), size).await
    }
    async fn open_legacy(
        &self,
        key: &str,
        size: u64,
    ) -> CoreResult<Option<Box<dyn memoswish_core::asset_read::ObjectReader>>> {
        self.open_snapshot(key, "", None, size).await
    }

    async fn read_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        limit: u64,
    ) -> CoreResult<Option<StoredObject>> {
        use memoswish_core::assets::ObjectVersion;
        version.validate()?;
        let id = match version {
            ObjectVersion::Unknown => return Err(CoreError::Conflict("object version is unknown".into())),
            ObjectVersion::Unversioned => "null",
            ObjectVersion::VersionId(id) => id,
        };
        self.read_bounded(key, &format!("versionId={}", uri_encode(id, true)), Some(id), limit).await
    }

    async fn read_legacy(&self, key: &str, limit: u64) -> CoreResult<Option<StoredObject>> {
        self.read_bounded(key, "", None, limit).await
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        Ok(self.put_versioned(key, bytes, mime).await?.asset)
    }

    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<bool> {
        validate_key(key)?;
        let response = self.send_request(Method::PUT, key, bytes, Some(mime), ("", true), &[]).await?;
        match response.status() {
            reqwest::StatusCode::OK | reqwest::StatusCode::CREATED => Ok(true),
            reqwest::StatusCode::PRECONDITION_FAILED => Ok(false),
            _ => Err(CoreError::Unavailable("conditional S3 create remains pending".into())),
        }
    }

    async fn put_versioned(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> CoreResult<memoswish_core::store::ObjectWrite> {
        validate_key(key)?;
        let sha = sha256_hex(&bytes);
        let len = bytes.len() as u64;
        let resp = self.send_signed(Method::PUT, key, bytes, Some(mime)).await?;
        if !resp.status().is_success() {
            return Err(CoreError::internal("S3 put failed"));
        }
        let version = resp
            .headers()
            .get("x-amz-version-id")
            .map(|v| v.to_str().map(str::to_owned).map_err(|_| CoreError::internal("S3 response processing failed")))
            .transpose()?;
        Ok(memoswish_core::store::ObjectWrite {
            asset: AssetRef {
                key: key.to_string(),
                url: self.url_for(key),
                mime: mime.to_string(),
                bytes: len,
                sha256: sha,
            },
            version,
        })
    }

    async fn delete_write(&self, key: &str, version: Option<&str>) -> CoreResult<()> {
        validate_key(key)?;
        // 未启用版本或暂停版本时删除 null 版本，避免创建删除标记。
        let query = format!("versionId={}", uri_encode(version.unwrap_or("null"), true));
        let response = self.send_signed_query(Method::DELETE, key, Vec::new(), None, &query).await?;
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            return Err(CoreError::internal("S3 written version deletion failed"));
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        validate_key(key)?;
        let resp = self.send_signed(Method::GET, key, Vec::new(), None).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(CoreError::internal("S3 get failed"));
        }
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| mime_from_key(key).to_string());
        let bytes = resp.bytes().await.map_err(|_| CoreError::internal("S3 response processing failed"))?.to_vec();
        Ok(Some(StoredObject { bytes, mime }))
    }

    async fn exists(&self, key: &str) -> CoreResult<bool> {
        validate_key(key)?;
        let resp = self.send_signed(Method::HEAD, key, Vec::new(), None).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if resp.status().is_success() {
            return Ok(true);
        }
        Err(CoreError::internal(format!("s3 head `{key}` failed with status {}", resp.status())))
    }

    async fn delete(&self, key: &str) -> CoreResult<()> {
        validate_key(key)?;
        let resp = self.send_signed(Method::DELETE, key, Vec::new(), None).await?;
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(CoreError::internal("S3 delete failed"))
    }

    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        validate_key(prefix.trim_end_matches('/'))?;
        if !prefix.ends_with('/') {
            return Err(CoreError::invalid("object listing requires a directory prefix"));
        }
        #[derive(Deserialize)]
        struct Entry {
            #[serde(rename = "Key")]
            key: String,
        }
        #[derive(Deserialize)]
        struct Page {
            #[serde(rename = "Contents", default)]
            entries: Vec<Entry>,
            #[serde(rename = "IsTruncated", default)]
            truncated: bool,
            #[serde(rename = "NextContinuationToken")]
            next: Option<String>,
        }
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        let mut seen_tokens = std::collections::HashSet::new();
        loop {
            let mut params =
                std::collections::BTreeMap::from([("list-type", "2".to_string()), ("prefix", prefix.to_string())]);
            if let Some(t) = &token {
                params.insert("continuation-token", t.clone());
            }
            let query = params
                .iter()
                .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
                .collect::<Vec<_>>()
                .join("&");
            let mut response = self.send_signed_query(Method::GET, "", Vec::new(), None, &query).await?;
            if !response.status().is_success() {
                return Err(CoreError::internal("S3 object listing failed"));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) =
                response.chunk().await.map_err(|_| CoreError::internal("S3 response processing failed"))?
            {
                if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
                    return Err(CoreError::internal("S3 listing page exceeds size limit"));
                }
                bytes.extend_from_slice(&chunk);
            }
            let page: Page = quick_xml::de::from_str(
                std::str::from_utf8(&bytes).map_err(|_| CoreError::internal("S3 response processing failed"))?,
            )
            .map_err(|_| CoreError::internal("S3 response processing failed"))?;
            for e in page.entries {
                validate_key(&e.key)?;
                if !e.key.starts_with(prefix) {
                    return Err(CoreError::internal("S3 listing returned an object outside the prefix"));
                }
                keys.push(e.key);
            }
            if !page.truncated {
                break;
            }
            let next = page
                .next
                .filter(|n| !n.is_empty() && n.len() < 8192)
                .ok_or_else(|| CoreError::internal("S3 listing omitted continuation token"))?;
            if !seen_tokens.insert(next.clone()) {
                return Err(CoreError::internal("S3 listing repeated continuation token"));
            }
            token = Some(next);
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn purge_prefix(&self, prefix: &str) -> CoreResult<()> {
        validate_key(prefix.trim_end_matches('/'))?;
        if !prefix.ends_with('/') {
            return Err(CoreError::invalid("object purge requires a directory prefix"));
        }
        #[derive(Deserialize)]
        struct Version {
            #[serde(rename = "Key")]
            key: String,
            #[serde(rename = "VersionId")]
            id: String,
        }
        #[derive(Deserialize)]
        struct Page {
            #[serde(rename = "Version", default)]
            versions: Vec<Version>,
            #[serde(rename = "DeleteMarker", default)]
            markers: Vec<Version>,
            #[serde(rename = "IsTruncated", default)]
            truncated: bool,
            #[serde(rename = "NextKeyMarker")]
            key: Option<String>,
            #[serde(rename = "NextVersionIdMarker")]
            version: Option<String>,
        }
        let mut empty = 0;
        for _ in 0..8 {
            let mut pending = Vec::new();
            let mut marker: Option<(String, String)> = None;
            let mut seen_markers = std::collections::HashSet::new();
            loop {
                let mut params =
                    std::collections::BTreeMap::from([("versions", String::new()), ("prefix", prefix.to_string())]);
                if let Some((key, version)) = &marker {
                    params.insert("key-marker", key.clone());
                    params.insert("version-id-marker", version.clone());
                }
                let query = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
                    .collect::<Vec<_>>()
                    .join("&");
                let mut response = self.send_signed_query(Method::GET, "", Vec::new(), None, &query).await?;
                if !response.status().is_success() {
                    return Err(CoreError::internal(
                        "S3 version listing failed; erasure requires ListBucketVersions permission",
                    ));
                }
                let mut bytes = Vec::new();
                while let Some(chunk) =
                    response.chunk().await.map_err(|_| CoreError::internal("S3 response processing failed"))?
                {
                    if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
                        return Err(CoreError::internal("S3 version listing exceeds size limit"));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                let page: Page = quick_xml::de::from_str(
                    std::str::from_utf8(&bytes).map_err(|_| CoreError::internal("S3 response processing failed"))?,
                )
                .map_err(|_| CoreError::internal("S3 response processing failed"))?;
                for version in page.versions.into_iter().chain(page.markers) {
                    validate_key(&version.key)?;
                    if !version.key.starts_with(prefix) || version.id.is_empty() || version.id.len() > 8192 {
                        return Err(CoreError::internal("S3 returned invalid object version"));
                    }
                    pending.push(version);
                }
                if !page.truncated {
                    break;
                }
                let next = (
                    page.key
                        .filter(|s| !s.is_empty() && s.len() <= 512)
                        .ok_or_else(|| CoreError::internal("S3 omitted version key marker"))?,
                    page.version.unwrap_or_default(),
                );
                if next.1.len() > 8192 || !seen_markers.insert(next.clone()) {
                    return Err(CoreError::internal("S3 repeated or invalid version marker"));
                }
                marker = Some(next);
            }
            if pending.is_empty() {
                empty += 1;
                if empty == 2 {
                    return Ok(());
                }
            } else {
                empty = 0;
            }
            // 先完成分页，再删除版本，避免删除 marker 所指版本改变后续分页位置。
            for version in pending {
                let query = format!("versionId={}", uri_encode(&version.id, true));
                let response = self.send_signed_query(Method::DELETE, &version.key, Vec::new(), None, &query).await?;
                if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
                    return Err(CoreError::internal("S3 object version deletion failed"));
                }
            }
        }
        Err(CoreError::internal("S3 version purge did not reach stable empty state"))
    }

    fn url_for(&self, key: &str) -> String {
        if validate_key(key).is_err() {
            return String::new();
        }
        if let Some(base) = &self.config.public_base_url {
            return format!("{}/{}", base.trim_end_matches('/'), encode_path(key));
        }
        if !self.config.access_key_id.is_empty() && !self.config.secret_access_key.is_empty() {
            return self.presign_get_url(key, self.config.presign_ttl_secs.max(1));
        }
        self.presign_get_url(key, self.config.presign_ttl_secs)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use chrono::TimeZone;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// 内存模拟对象存储表类型。
    type MockBucket = Arc<Mutex<HashMap<String, (Vec<u8>, String)>>>;

    /// 启动轻量级内存 S3 模拟服务端，校验 SigV4 请求头并处理 PUT / GET / HEAD / DELETE。
    async fn spawn_mock_s3() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let objects: MockBucket = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let objects = objects.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end = loop {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };

                    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let mut lines = header_text.split("\r\n");
                    let request_line = lines.next().unwrap_or_default();
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or_default();
                    let path = parts.next().unwrap_or_default();

                    let mut headers = HashMap::new();
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                        }
                    }

                    let content_len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                    while buf.len() < header_end + content_len {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body = buf[header_end..header_end + content_len].to_vec();

                    if !super::signing_tests::verify(method, path, &headers, &body, Utc::now().timestamp()) {
                        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
                        return;
                    }
                    let parsed = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
                    let query: Vec<_> = parsed
                        .query_pairs()
                        .filter(|(k, _)| !k.starts_with("X-Amz-"))
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect();
                    let mut route = parsed.clone();
                    route.set_query(None);
                    for (k, v) in query {
                        route.query_pairs_mut().append_pair(&k, &v);
                    }
                    let path = route.as_str().strip_prefix("http://localhost").unwrap();
                    match method {
                        "PUT" => {
                            let mime = headers
                                .get("content-type")
                                .cloned()
                                .unwrap_or_else(|| "application/octet-stream".into());
                            let exists = {
                                let mut objects = objects.lock().unwrap();
                                if headers.get("if-none-match").is_some_and(|h| h == "*") && objects.contains_key(path)
                                {
                                    true
                                } else {
                                    objects.insert(path.to_string(), (body, mime));
                                    false
                                }
                            };
                            if exists {
                                let _ = stream
                                    .write_all(b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n")
                                    .await;
                                return;
                            }
                            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
                        }
                        "GET" if path.contains('?') => {
                            let url = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
                            let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
                            let versions = query.contains_key("versions");
                            if !versions {
                                assert_eq!(query["list-type"], "2");
                            }
                            let prefix = format!("/memoswish-test/{}", query["prefix"]);
                            let mut matched = objects
                                .lock()
                                .unwrap()
                                .keys()
                                .filter(|k| k.starts_with(&prefix))
                                .cloned()
                                .collect::<Vec<_>>();
                            matched.sort();
                            let offset = if versions {
                                query
                                    .get("key-marker")
                                    .map(|marker| {
                                        matched
                                            .iter()
                                            .take_while(|key| {
                                                key.trim_start_matches("/memoswish-test/") <= marker.as_str()
                                            })
                                            .count()
                                    })
                                    .unwrap_or(0)
                            } else {
                                query.get("continuation-token").map(|n| n.parse::<usize>().unwrap()).unwrap_or(0)
                            };
                            let entries = matched
                                .iter()
                                .skip(offset)
                                .take(1)
                                .map(|k| {
                                    if versions {
                                        format!(
                                            "<Version><Key>{}</Key><VersionId>null</VersionId></Version>",
                                            k.trim_start_matches("/memoswish-test/")
                                        )
                                    } else {
                                        format!(
                                            "<Contents><Key>{}</Key></Contents>",
                                            k.trim_start_matches("/memoswish-test/")
                                        )
                                    }
                                })
                                .collect::<String>();
                            let next = offset + 1;
                            let truncated = next < matched.len();
                            let token = if truncated {
                                if versions {
                                    format!(
                                        "<NextKeyMarker>{}</NextKeyMarker><NextVersionIdMarker>null</NextVersionIdMarker>",
                                        matched[offset].trim_start_matches("/memoswish-test/")
                                    )
                                } else {
                                    format!("<NextContinuationToken>{next}</NextContinuationToken>")
                                }
                            } else {
                                String::new()
                            };
                            let body = format!(
                                "<ListBucketResult><IsTruncated>{truncated}</IsTruncated>{entries}{token}</ListBucketResult>"
                            );
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                            stream.write_all(response.as_bytes()).await.unwrap();
                        }
                        "GET" => {
                            let found = objects.lock().unwrap().get(path).cloned();
                            match found {
                                Some((bytes, mime)) => {
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\r\n",
                                        bytes.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.write_all(&bytes).await;
                                }
                                None => {
                                    let _ =
                                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                                }
                            }
                        }
                        "HEAD" => {
                            let found = objects.lock().unwrap().get(path).cloned();
                            match found {
                                Some((bytes, mime)) => {
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\r\n",
                                        bytes.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                }
                                None => {
                                    let _ =
                                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                                }
                            }
                        }
                        "DELETE" => {
                            objects.lock().unwrap().remove(path.split('?').next().unwrap());
                            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                        }
                        _ => {
                            let _ =
                                stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n").await;
                        }
                    }
                });
            }
        });

        format!("http://{addr}")
    }

    #[tokio::test]
    async fn conditional_shared_creation_is_immutable_across_competing_and_late_writes() {
        let endpoint = spawn_mock_s3().await;
        let store = S3Store::new(S3Config {
            endpoint,
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ..Default::default()
        })
        .unwrap();
        let key = "shared/deployment-v1.sha256";
        let (a, b) = tokio::join!(
            store.put_if_absent(key, b"first".to_vec(), "text/plain"),
            store.put_if_absent(key, b"second".to_vec(), "text/plain")
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_ne!(a, b);
        let expected = if a { b"first".to_vec() } else { b"second".to_vec() };
        assert!(!store.put_if_absent(key, b"late".to_vec(), "text/plain").await.unwrap());
        assert_eq!(store.get(key).await.unwrap().unwrap().bytes, expected);
    }

    #[tokio::test]
    async fn s3_put_get_exists_delete_and_presign() {
        let endpoint = spawn_mock_s3().await;
        let store = S3Store::new(S3Config {
            endpoint: endpoint.clone(),
            bucket: "memoswish-test".into(),
            region: "us-east-1".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            public_base_url: None,
            presign_ttl_secs: 900,
        })
        .unwrap();

        let key = "tenants/t1/tts/sample.wav";
        assert!(!store.exists(key).await.unwrap());
        assert!(store.get(key).await.unwrap().is_none());

        let asset = store.put(key, b"RIFF-WAVE".to_vec(), "audio/wav").await.unwrap();
        assert_eq!(asset.key, key);
        assert_eq!(asset.bytes, 9);
        assert!(asset.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(asset.url.contains("X-Amz-Expires=900"));
        assert!(asset.url.contains("X-Amz-Signature="));

        assert!(store.exists(key).await.unwrap());
        let obj = store.get(key).await.unwrap().unwrap();
        assert_eq!(obj.bytes, b"RIFF-WAVE");
        assert_eq!(obj.mime, "audio/wav");

        // 路径穿越等非法键必须被拦截。
        assert!(store.put("../escape", b"x".to_vec(), "text/plain").await.is_err());
        assert!(store.get("../escape").await.is_err());
        assert!(store.exists("../escape").await.is_err());
        assert!(store.delete("../escape").await.is_err());

        store.put("tenants/t1/images/b.png", b"PNG".to_vec(), "image/png").await.unwrap();
        store.put("tenants/t10/images/a.png", b"other tenant".to_vec(), "image/png").await.unwrap();
        assert_eq!(store.list_prefix("tenants/t1/").await.unwrap(), vec!["tenants/t1/images/b.png", key]);
        assert!(store.list_prefix("tenants/t1").await.is_err());
        assert!(store.list_prefix("tenants/missing/").await.unwrap().is_empty());
        store.purge_prefix("tenants/t1/").await.unwrap();
        assert!(store.list_prefix("tenants/t1/").await.unwrap().is_empty());
        assert!(store.exists("tenants/t10/images/a.png").await.unwrap());
        store.delete(key).await.unwrap();
        assert!(!store.exists(key).await.unwrap());
        assert!(store.get(key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn purge_deletes_all_versions_and_markers_with_exact_prefix() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut deleted = Vec::new();
            for _ in 0..9 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 16384];
                let n = stream.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]);
                let line = request.lines().next().unwrap();
                let mut words = line.split_whitespace();
                let method = words.next().unwrap();
                let target = words.next().unwrap();
                let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
                let body = if method == "DELETE" {
                    assert_eq!(url.path(), "/memoswish-test/tenants/t1/a.png");
                    deleted.push(params["versionId"].clone());
                    String::new()
                } else if params.contains_key("versions") {
                    if deleted.len() == 4 {
                        "<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>".into()
                    } else if deleted.len() == 3 {
                        // 第一次枚举结束后到达的新版本仍必须按 versionId 删除。
                        "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>tenants/t1/a.png</Key><VersionId>late-put</VersionId></Version></ListVersionsResult>".into()
                    } else if params.contains_key("key-marker") {
                        assert!(deleted.is_empty(), "version pagination must complete before deletion");
                        assert_eq!(params["version-id-marker"], "v+one/=");
                        "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>tenants/t1/a.png</Key><VersionId>old</VersionId></Version><DeleteMarker><Key>tenants/t1/a.png</Key><VersionId>d&amp;1</VersionId></DeleteMarker></ListVersionsResult>".into()
                    } else {
                        "<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>tenants/t1/a.png</NextKeyMarker><NextVersionIdMarker>v+one/=</NextVersionIdMarker><Version><Key>tenants/t1/a.png</Key><VersionId>v+one/=</VersionId></Version></ListVersionsResult>".into()
                    }
                } else {
                    "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>".into()
                };
                let response =
                    format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            deleted
        });
        let store = S3Store::new(S3Config { endpoint, bucket: "memoswish-test".into(), ..Default::default() }).unwrap();
        store.purge_prefix("tenants/t1/").await.unwrap();
        assert_eq!(task.await.unwrap(), vec!["v+one/=", "old", "d&1", "late-put"]);
    }

    #[tokio::test]
    async fn purge_rejects_version_outside_the_requested_directory() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n >= 4 && &buf[..4] == b"GET ");
            let body = "<ListVersionsResult><Version><Key>tenants/t10/a.png</Key><VersionId>v1</VersionId></Version></ListVersionsResult>";
            stream
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                        .as_bytes(),
                )
                .await
                .unwrap();
        });
        let store = S3Store::new(S3Config { endpoint, ..Default::default() }).unwrap();
        assert!(store.purge_prefix("tenants/t1/").await.is_err());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn put_receipt_compensation_deletes_exact_version_without_marker() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for versioned in [true, false] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 8192];
                let n = stream.read(&mut bytes).await.unwrap();
                assert!(
                    std::str::from_utf8(&bytes[..n]).unwrap().starts_with("PUT /memoswish-test/tenants/t1/a?X-Amz-")
                );
                let version_header = if versioned { "x-amz-version-id: v+one/=\r\n" } else { "" };
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{version_header}Content-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                let (mut stream, _) = listener.accept().await.unwrap();
                let n = stream.read(&mut bytes).await.unwrap();
                let request = std::str::from_utf8(&bytes[..n]).unwrap();
                let expected = if versioned { "v%2Bone%2F%3D" } else { "null" };
                assert!(
                    request.starts_with("DELETE /memoswish-test/tenants/t1/a?X-Amz-")
                        && request.lines().next().unwrap().contains(&format!("&versionId={expected}&X-Amz-Signature=")),
                    "{request}"
                );
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let store = S3Store::new(S3Config { endpoint, bucket: "memoswish-test".into(), ..Default::default() }).unwrap();
        for expected in [Some("v+one/="), None] {
            let write = store.put_versioned("tenants/t1/a", vec![1], "image/png").await.unwrap();
            assert_eq!(write.version.as_deref(), expected);
            store.delete_write(&write.asset.key, write.version.as_deref()).await.unwrap();
        }
        task.await.unwrap();
    }

    #[test]
    fn presign_get_url_is_deterministic() {
        let store = S3Store::from_config(S3Config {
            endpoint: "https://s3.us-east-1.amazonaws.com".into(),
            bucket: "my-bucket".into(),
            region: "us-east-1".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            public_base_url: None,
            presign_ttl_secs: 3600,
        });
        let fixed = Utc.with_ymd_and_hms(2026, 5, 24, 0, 0, 0).unwrap();
        let url = store.presign_get_url_at("tenants/local/tts/hello.wav", 86400, fixed);
        assert!(url.starts_with(
            "https://s3.us-east-1.amazonaws.com/my-bucket/tenants/local/tts/hello.wav?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        ));
        assert!(url.contains("X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260524%2Fus-east-1%2Fs3%2Faws4_request"));
        assert!(url.contains("X-Amz-Date=20260524T000000Z"));
        assert!(url.contains("X-Amz-Expires=86400"));
        assert!(url.contains("X-Amz-SignedHeaders=host"));
        assert_eq!(url, store.presign_get_url_at("tenants/local/tts/hello.wav", 86400, fixed));
    }
}

#[cfg(test)]
mod purge_bound_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn s3_non_quiescent_versions_keep_erasure_pending_after_bounded_retries() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut listings = 0;
            for _ in 0..16 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 8192];
                let n = stream.read(&mut bytes).await.unwrap();
                let request = std::str::from_utf8(&bytes[..n]).unwrap();
                let body = if request.starts_with("GET ") {
                    assert!(request.lines().next().unwrap().contains("versions="));
                    listings += 1;
                    "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>tenants/t1/a</Key><VersionId>new</VersionId></Version></ListVersionsResult>"
                } else {
                    assert!(request.lines().next().unwrap().contains("versionId=new"));
                    ""
                };
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
            listings
        });
        let store = S3Store::new(S3Config { endpoint, ..Default::default() }).unwrap();
        assert!(store.purge_prefix("tenants/t1/").await.is_err());
        assert_eq!(task.await.unwrap(), 8);
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;
    use memoswish_core::assets::ObjectVersion;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn exact_version_bounded_read_never_follows_redirects_or_latest() {
        for (headers, body, allowed) in [
            ("200 OK\r\nx-amz-version-id: v-old\r\nContent-Length: 3", "abc", true),
            ("200 OK\r\nx-amz-version-id: v-new\r\nContent-Length: 3", "abc", false),
            ("200 OK\r\nContent-Length: 3", "abc", false),
            ("200 OK\r\nx-amz-version-id: v-old\r\nContent-Length: 4", "abcd", false),
            ("200 OK\r\nx-amz-version-id: v-old\r\nTransfer-Encoding: chunked", "4\r\nabcd\r\n0\r\n\r\n", false),
            ("302 Found\r\nLocation: http://127.0.0.1:1/SECRET_SENTINEL\r\nContent-Length: 0", "", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let count = socket.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request.starts_with("GET /bucket/tenants/t/object?X-Amz-")
                        && request.lines().next().unwrap().contains("&versionId=v-old&X-Amz-Signature=")
                );
                let response =
                    format!("HTTP/1.1 {headers}\r\nContent-Type: image/png\r\nConnection: close\r\n\r\n{body}");
                let _ = socket.write_all(response.as_bytes()).await;
            });
            let config = S3Config {
                endpoint: format!("http://{address}"),
                bucket: "bucket".into(),
                region: "test".into(),
                ..S3Config::default()
            };
            let store = S3Store::new(config.clone()).unwrap();
            let result = store.read_delivery("tenants/t/object", &ObjectVersion::VersionId("v-old".into()), 3).await;
            if allowed {
                assert_eq!(result.unwrap().unwrap().bytes, b"abc");
            } else {
                assert!(result.is_err());
                assert!(!format!("{:?}", result.err()).contains("SECRET_SENTINEL"));
            }
            server.await.unwrap();
            assert!(store.read_delivery("tenants/t/object", &ObjectVersion::Unknown, 3).await.is_err());
            let another = S3Store::new(S3Config { bucket: "another".into(), ..config }).unwrap();
            assert_ne!(store.namespace().unwrap(), another.namespace().unwrap());
        }
    }
}

#[cfg(test)]
#[path = "s3_signing_tests.rs"]
mod signing_tests;

impl S3Store {
    async fn open_snapshot(
        &self,
        key: &str,
        query: &str,
        expected_version: Option<&str>,
        size: u64,
    ) -> CoreResult<Option<Box<dyn memoswish_core::asset_read::ObjectReader>>> {
        validate_key(key)?;
        if size > 64 * 1024 * 1024 {
            return Err(CoreError::invalid("asset exceeds delivery limit"));
        }
        let response = self.send_signed_query(Method::HEAD, key, vec![], None, query).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let value = |name| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let version = value("x-amz-version-id");
        let length = value("content-length").and_then(|v| v.parse::<u64>().ok());
        let etag = value("etag")
            .filter(|e| e.starts_with('"') && e.ends_with('"') && !e.contains('\r') && !e.contains('\n'))
            .ok_or_else(|| CoreError::Conflict("S3 object lacks a strong identity".into()))?;
        if response.status() != reqwest::StatusCode::OK
            || length != Some(size)
            || expected_version.is_some_and(|v| version.as_deref() != Some(v))
        {
            return Err(CoreError::Conflict("S3 metadata identity mismatch".into()));
        }
        let mime = value("content-type").unwrap_or_else(|| mime_from_key(key).into());
        let identity = sha256_hex(format!("{version:?}\0{etag}\0{size}\0{mime}").as_bytes());
        let query = version.as_deref().map(|v| format!("versionId={}", uri_encode(v, true))).unwrap_or_default();
        Ok(Some(Box::new(S3Reader {
            store: self.clone(),
            key: key.into(),
            query,
            version,
            etag,
            metadata: memoswish_core::asset_read::ReadIdentity { cacheable: true, identity, size, mime },
        })))
    }
}

struct S3Reader {
    store: S3Store,
    key: String,
    query: String,
    version: Option<String>,
    etag: String,
    metadata: memoswish_core::asset_read::ReadIdentity,
}

#[async_trait]
impl memoswish_core::asset_read::ObjectReader for S3Reader {
    fn metadata(&self) -> &memoswish_core::asset_read::ReadIdentity {
        &self.metadata
    }
    async fn read_at(&mut self, offset: u64, length: usize) -> CoreResult<Vec<u8>> {
        if length == 0
            || length > memoswish_core::asset_read::BLOCK_BYTES
            || offset.checked_add(length as u64).is_none_or(|end| end > self.metadata.size)
        {
            return Err(CoreError::invalid("S3 read exceeds block bounds"));
        }
        let range = format!("bytes={offset}-{}", offset + length as u64 - 1);
        let mut response = self
            .store
            .send_request(
                Method::GET,
                &self.key,
                vec![],
                None,
                (&self.query, false),
                &[("range", &range), ("if-match", &self.etag)],
            )
            .await?;
        let value = |name| response.headers().get(name).and_then(|v| v.to_str().ok());
        let expected = format!("bytes {offset}-{}/{}", offset + length as u64 - 1, self.metadata.size);
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT
            || value("content-range") != Some(expected.as_str())
            || value("x-amz-version-id") != self.version.as_deref()
            || value("etag") != Some(self.etag.as_str())
            || value("content-type") != Some(self.metadata.mime.as_str())
            || response.content_length() != Some(length as u64)
        {
            return Err(CoreError::Conflict("S3 range identity mismatch".into()));
        }
        let mut bytes = Vec::with_capacity(length);
        while let Some(chunk) =
            response.chunk().await.map_err(|_| CoreError::Unavailable("S3 range read failed".into()))?
        {
            if chunk.len() > length - bytes.len() {
                return Err(CoreError::Conflict("S3 range exceeds declared size".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != length {
            return Err(CoreError::Conflict("S3 range truncated".into()));
        }
        Ok(bytes)
    }
}
