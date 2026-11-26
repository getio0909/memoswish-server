//! S3 配置保持可解析，未编译 S3 的守护进程明确拒绝选择该后端。
use serde::{Deserialize, Serialize};

/// S3 兼容对象存储配置。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct S3Config {
    /// S3 端点 URL，例如 `https://s3.us-east-1.amazonaws.com` 或 `http://127.0.0.1:9000`。
    pub endpoint: String,
    /// 存储桶名称。
    pub bucket: String,
    /// 区域标识，例如 `us-east-1` 或 `auto`。
    pub region: String,
    /// 访问密钥 ID（Access Key ID）。
    pub access_key_id: String,
    /// 秘密访问密钥（Secret Access Key）。
    pub secret_access_key: String,
    /// 可选的公开访问基地址（配置 CDN 或公开桶时直接拼接，否则生成预签名 URL）。
    pub public_base_url: Option<String>,
    /// `url_for` 生成预签名 URL 的默认有效期（秒），默认 3600。
    pub presign_ttl_secs: u64,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "learntok".into(),
            region: "us-east-1".into(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            public_base_url: None,
            presign_ttl_secs: 3600,
        }
    }
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config").finish_non_exhaustive()
    }
}
