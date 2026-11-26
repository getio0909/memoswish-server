//! 配置：默认值 ← TOML 文件 ← 环境变量（`MEMOSWISH_*`）← 命令行参数。

use std::path::{Path, PathBuf};

use anyhow::Context;
use memoswish_content::AiExplainConfig;
use memoswish_feed::FeedConfig;
use memoswish_media::tts::command::CommandTtsConfig;
use memoswish_media::tts::http::HttpTtsConfig;
use memoswish_protocol::DeploymentMode;
use serde::{Deserialize, Serialize};

mod diagnostics;
mod environment;
pub(crate) mod key_file;
mod validation;

#[cfg(all(test, feature = "sqlite"))]
mod explanation_tests;

/// memoswishd 配置。示例见 `server/config/memoswishd.example.toml`。
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 每租户可同时保留的未完成导入数量。
    pub import_staging_limit: i64,
    pub profile: crate::deployment::Profile,
    pub role: crate::deployment::Role,
    pub admission: crate::admission::AdmissionConfig,
    pub password_profile: crate::password_mail::PasswordProfile,
    pub smtp: crate::password_mail::SmtpConfig,
    pub password_work: memoswish_auth::password::PasswordConfig,
    pub proxy_trust: crate::auth_defenses::ProxyTrust,
    /// 监听地址。局域网或远程设备请使用 `deploy/single-instance` 的认证 HTTPS 部署。
    /// 将 `single_user` 暴露到回环以外会让所有能连接服务的客户端获得所有者权限。
    pub bind: String,
    /// 所有角色的独立探针监听器；默认回环随机端口，部署时显式固定端口。
    pub health_bind: String,
    /// `single_user`（自托管免登）或 `multi_tenant`（JWT / API Token）。
    pub mode: DeploymentMode,
    /// 数据目录：SQLite 数据库、对象存储、自动生成的 JWT 密钥。
    pub data_dir: PathBuf,
    /// 数据库 URL：`sqlite://...` 或 `postgres://...`；为空时使用 `<data_dir>/learntok.db`。
    /// 参考条件：SQLite URL 需 feature sqlite，PostgreSQL URL 需 feature postgres。
    pub database_url: Option<String>,
    /// 数据库连接上限，显式值必须为正；省略时 SQLite 文件库 8、内存库 1、PostgreSQL 10。
    pub db_max_connections: Option<u32>,
    pub object_store: ObjectStoreConfig,
    /// JWT 密钥（≥ 32 字节）；为空时自动生成并保存在 `<data_dir>/jwt_secret`。
    pub jwt_secret: Option<String>,
    pub jwt_ttl_secs: u64,
    pub jwt_key_id: Option<String>,
    pub jwt_keys: std::collections::BTreeMap<String, memoswish_auth::token::VerificationKey>,
    pub jwt_legacy_key_until: Option<i64>,
    pub sessions: memoswish_auth::sessions::SessionConfig,
    /// 多租户模式下是否开放注册。
    pub registration_open: bool,
    /// 新租户默认套餐（`free` / `pro` / `team` / `self_hosted`）。
    pub default_plan: String,
    /// 首次启动时写入演示卡组。
    pub seed_demo: bool,
    /// 允许跨域访问 HTTP API 的 Origin（仅 Flutter Web / 浏览器管理后台需要）；`*` 表示任意，仅限开发。
    /// 默认为空：单用户模式免登录，开放 CORS 会让任意网页读取本机学习数据。
    pub cors_origins: Vec<String>,
    pub tts: TtsConfig,
    pub mcp: McpConfig,
    /// 参考条件：启用时需 feature mcp-oauth，mode = multi_tenant，mcp.http_enabled = true。
    pub oauth: memoswish_auth::oauth_config::OAuthConfig,
    /// 参考条件：启用时需 feature oidc，mode = multi_tenant。
    pub oidc: memoswish_auth::oidc_config::OidcConfig,
    /// FSRS-6 与可变奖赏信息流参数。
    pub feed: FeedConfig,
    /// AI 卡片深度解析配置（未配置外部 API 时自动回退到内置启发式解析）。
    pub ai: AiExplainConfig,
    pub privacy: memoswish_protocol::PrivacyPolicy,
    pub diagnostic_forwarding: crate::diagnostics::ForwardingConfig,
}

/// 对象存储选择；S3 凭据通过环境覆盖，默认使用本地磁盘。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObjectStoreConfig {
    pub backend: String,
    /// 同时拥有写入及补偿的后台任务上限。
    pub max_concurrent_puts: usize,
    /// 创建后台任务前等待空位的最长毫秒数。
    pub put_admission_timeout_ms: u64,
    /// 关闭时等待后台写入及补偿的最长秒数。
    pub put_shutdown_timeout_secs: u64,
    /// 参考条件：feature s3（commercial-saas 已包含），object_store.backend = s3。
    pub s3: memoswish_storage::S3Config,
}
impl Default for ObjectStoreConfig {
    fn default() -> Self {
        Self {
            backend: "local".into(),
            max_concurrent_puts: 32,
            put_admission_timeout_ms: 250,
            put_shutdown_timeout_secs: 65,
            s3: Default::default(),
        }
    }
}

/// TTS 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TtsConfig {
    /// 默认引擎 ID。
    pub default_engine: String,
    /// 显式注册本地 eSpeak；实际可用性由有界诊断确认。
    pub auto_detect_espeak: bool,
    /// 额外的命令行引擎。
    pub commands: Vec<CommandTtsConfig>,
    /// 额外的 HTTP / 云端神经语音引擎。
    pub http: Vec<HttpTtsConfig>,
}

/// MCP 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// 是否在 HTTP 服务上挂载 `/mcp`。
    pub http_enabled: bool,
    /// 允许的浏览器 Origin（本机 Origin 始终允许）。
    pub allowed_origins: Vec<String>,
    /// 可信 MCP Host 名或 host:port，用于防止 DNS 重绑定。
    pub allowed_hosts: Vec<String>,
    /// 每租户令牌桶容量。
    pub rate_limit_burst: u32,
    /// 每租户每秒补充令牌数。
    pub rate_limit_per_sec: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            import_staging_limit: 2,
            profile: Default::default(),
            role: Default::default(),
            admission: Default::default(),
            password_profile: Default::default(),
            smtp: Default::default(),
            password_work: Default::default(),
            proxy_trust: Default::default(),
            bind: "127.0.0.1:8787".into(),
            health_bind: "127.0.0.1:0".into(),
            mode: DeploymentMode::SingleUser,
            data_dir: PathBuf::from("data"),
            database_url: None,
            db_max_connections: None,
            object_store: Default::default(),
            jwt_secret: None,
            jwt_ttl_secs: 7 * 24 * 3600,
            jwt_key_id: None,
            jwt_keys: Default::default(),
            jwt_legacy_key_until: None,
            sessions: Default::default(),
            registration_open: false,
            default_plan: "self_hosted".into(),
            seed_demo: true,
            cors_origins: vec![],
            tts: TtsConfig::default(),
            mcp: McpConfig::default(),
            oauth: Default::default(),
            oidc: Default::default(),
            feed: FeedConfig::default(),
            ai: AiExplainConfig::default(),
            privacy: Default::default(),
            diagnostic_forwarding: Default::default(),
        }
    }
}

impl Default for TtsConfig {
    fn default() -> Self {
        Self { default_engine: "unconfigured".into(), auto_detect_espeak: false, commands: vec![], http: vec![] }
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            http_enabled: true,
            allowed_origins: vec![],
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
            rate_limit_burst: 120,
            rate_limit_per_sec: 4.0,
        }
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("profile", &self.profile).field("role", &self.role).finish_non_exhaustive()
    }
}

impl Config {
    /// 所有命令在解析配置和产生副作用前拒绝旧环境前缀。
    pub fn reject_legacy_environment() -> anyhow::Result<()> {
        environment::reject_legacy_names(std::env::vars_os().map(|(key, _)| key))
    }

    /// 加载可选 TOML 文件并应用环境变量覆盖。
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        Self::reject_legacy_environment()?;
        let mut cfg = match path {
            Some(p) => {
                let text =
                    std::fs::read_to_string(p).with_context(|| format!("failed to read config {}", p.display()))?;
                Self::parse(&text)?
            }
            None => Config::default(),
        };
        cfg.apply_env()?;
        Ok(cfg)
    }

    fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Self = serde_path_to_error::deserialize(toml::Deserializer::new(text)).map_err(|error| {
            // 严格子结构的未知键本身也可能是误填的凭据，不能进入诊断路径或原因。
            if error.inner().message().starts_with("unknown field `") {
                anyhow::anyhow!("config contains unknown fields")
            } else {
                diagnostics::sanitized(text, error)
            }
        })?;
        let mut unknown = false;
        let _: Self = serde_ignored::deserialize(toml::Deserializer::new(text), |_| unknown = true)
            .map_err(|_| anyhow::anyhow!("invalid config"))?;
        anyhow::ensure!(!unknown, "config contains unknown fields");
        Ok(cfg)
    }

    fn apply_env(&mut self) -> anyhow::Result<()> {
        *self = environment::merge_current(self)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn parse_with_env(text: &str, var: &impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        environment::merge(&Self::parse(text)?, var)
    }

    #[cfg(test)]
    fn apply_object_store_env(&mut self, var: &impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        *self = environment::merge(self, var)?;
        Ok(())
    }

    /// 生效的数据库 URL。
    pub fn database_url(&self) -> String {
        self.database_url.clone().unwrap_or_else(|| format!("sqlite://{}", self.data_dir.join("learntok.db").display()))
    }

    /// 环境覆盖完成后按最终后端解析省略值，显式正整数保持原值。
    pub fn database_max_connections(&self) -> anyhow::Result<u32> {
        if let Some(max) = self.db_max_connections {
            anyhow::ensure!(max > 0, "db_max_connections must be positive");
            return Ok(max);
        }
        let url = self.database_url();
        match memoswish_storage::DatabaseKind::from_url(&url)? {
            memoswish_storage::DatabaseKind::Postgres => Ok(10),
            #[cfg(feature = "sqlite")]
            memoswish_storage::DatabaseKind::Sqlite => {
                Ok(memoswish_storage::sqlite::SqliteRepository::default_max_connections(&url)?)
            }
            #[cfg(not(feature = "sqlite"))]
            memoswish_storage::DatabaseKind::Sqlite => anyhow::bail!("SQLite requires sqlite feature"),
        }
    }

    /// 对象存储根目录。
    pub fn assets_dir(&self) -> PathBuf {
        self.data_dir.join("assets")
    }

    /// 读取或生成 JWT 密钥。
    pub fn resolve_jwt_secret(&self) -> anyhow::Result<String> {
        if let Some(s) = &self.jwt_secret {
            anyhow::ensure!(s.trim().len() >= 32, "jwt_secret must be at least 32 bytes");
            return Ok(s.clone());
        }
        anyhow::ensure!(
            self.profile == crate::deployment::Profile::Embedded,
            "horizontal profile requires an explicit jwt_secret"
        );
        key_file::resolve(&self.data_dir.join("jwt_secret"))
    }

    /// 只读验证已有密钥；不存在时由持锁的启动流程负责发布。
    pub(crate) fn preflight_key(&self) -> anyhow::Result<()> {
        if self.jwt_secret.is_none() {
            key_file::read(&self.data_dir.join("jwt_secret"))?;
        }
        Ok(())
    }

    /// 窄维护只读取已有密钥，不能沿启动路径创建新密钥。
    pub(crate) fn existing_jwt_secret(&self) -> anyhow::Result<String> {
        if let Some(secret) = &self.jwt_secret {
            anyhow::ensure!(secret.trim().len() >= 32, "jwt_secret must be at least 32 bytes");
            return Ok(secret.clone());
        }
        key_file::read(&self.data_dir.join("jwt_secret"))?
            .ok_or_else(|| anyhow::anyhow!("existing installation key is required"))
    }

    /// 打印用的脱敏副本。
    pub fn redacted(&self) -> Config {
        let mut c = self.clone();
        c.smtp = c.smtp.redacted();
        c.tts.commands.clear();
        c.tts.http.clear();
        c.admission.redis_url = c.admission.redis_url.map(|_| "***".into());
        c.oidc = c.oidc.redacted();
        for k in c.jwt_keys.values_mut() {
            k.secret = "***".into();
        }
        c.object_store.s3.access_key_id = "***".into();
        c.object_store.s3.secret_access_key = "***".into();
        {
            let url = &mut c.object_store.s3.endpoint;
            if url::Url::parse(url).map_or(true, |u| {
                !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some()
            }) {
                *url = "***".into();
            }
        }
        c.object_store.s3.public_base_url = c.object_store.s3.public_base_url.map(|u| {
            if url::Url::parse(&u).is_ok_and(|v| {
                v.username().is_empty() && v.password().is_none() && v.query().is_none() && v.fragment().is_none()
            }) {
                u
            } else {
                "***".into()
            }
        });
        if c.jwt_secret.is_some() {
            c.jwt_secret = Some("***".into());
        }
        c.ai = c.ai.redacted();
        c.diagnostic_forwarding.endpoint = "***".into();
        c.diagnostic_forwarding.public_key = "***".into();
        c.diagnostic_forwarding.purpose_version = "***".into();
        for value in [&mut c.oauth.issuer, &mut c.oauth.public_base_url, &mut c.oauth.mcp_resource] {
            if !value.is_empty()
                && url::Url::parse(value).map_or(true, |u| {
                    !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some()
                })
            {
                *value = "***".into();
            }
        }
        c.database_url = c.database_url.map(|_| "***".into());
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config/memoswishd.example.toml");
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:8787");
        assert_eq!(cfg.mode, DeploymentMode::SingleUser);
        assert_eq!(cfg.feed, FeedConfig::default());
        let example: toml::Value = toml::from_str(text).unwrap();
        let defaults = toml::Value::try_from(FeedConfig::default()).unwrap();
        for (key, value) in example["feed"].as_table().unwrap() {
            assert_eq!(defaults.get(key), Some(value), "example feed field must match a real default: {key}");
        }
    }

    #[test]
    fn default_database_is_sqlite_in_data_dir() {
        let cfg = Config::default();
        assert!(cfg.database_url().starts_with("sqlite://"));
        assert!(cfg.database_url().ends_with("learntok.db"));
    }
}

#[cfg(test)]
mod oauth_redaction_tests {
    use super::*;
    #[test]
    fn oauth_url_credentials_are_not_printed_even_when_disabled() {
        let mut c = Config::default();
        c.oauth.issuer = "https://user:private-oauth-password@example.com".into();
        c.oauth.public_base_url = "https://example.com?token=private".into();
        c.oauth.mcp_resource = "invalid secret".into();
        let serialized = toml::to_string(&c.redacted()).unwrap();
        for secret in ["private-oauth-password", "token=private", "invalid secret"] {
            assert!(!serialized.contains(secret), "{serialized}");
        }
        assert!(!c.oauth.enabled);
    }
}

#[cfg(test)]
mod object_store_tests {
    use super::*;
    #[test]
    fn malformed_secret_config_never_enters_error_chain() {
        let path = std::env::temp_dir().join(format!("memoswish-config-{}.toml", memoswish_core::ids::new_id()));
        for text in [
            "[object_store.s3]\nsecret_access_key = \"synthetic-private-secret\",\n",
            "[object_store.s3]\nsecret_access_key = { value = \"synthetic-private-secret\" }\n",
            "[object_store.s3]\npresign_ttl_secs = \"synthetic-private-secret\"\n",
            "mode = \"synthetic-private-secret\"\n",
        ] {
            std::fs::write(&path, text).unwrap();
            let error = Config::load(Some(&path)).unwrap_err();
            for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
                assert!(!output.contains("synthetic-private-secret"), "{output}");
                assert!(output.contains("line "), "{output}");
                assert!(output.contains("column "), "{output}");
                assert!(output.contains("key "), "{output}");
            }
            assert_eq!(error.chain().count(), 1, "raw TOML error must not remain as a source");
            if text.contains("presign_ttl_secs") {
                assert!(error.to_string().contains("object_store.s3.presign_ttl_secs"));
            }
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn object_store_env_overrides_and_redacts_credentials() {
        let mut cfg = Config::default();
        let vars = std::collections::HashMap::from([
            ("MEMOSWISH_OBJECT_STORE", "s3"),
            ("MEMOSWISH_S3_ENDPOINT", "http://127.0.0.1:9000"),
            ("MEMOSWISH_S3_BUCKET", "custom-bucket"),
            ("MEMOSWISH_S3_REGION", "custom-region"),
            ("MEMOSWISH_S3_ACCESS_KEY_ID", "private-access-id"),
            ("MEMOSWISH_S3_SECRET_ACCESS_KEY", "private-secret-key"),
            ("MEMOSWISH_S3_PUBLIC_BASE_URL", "https://cdn.example/assets"),
            ("MEMOSWISH_S3_PRESIGN_TTL_SECS", "120"),
        ]);
        cfg.apply_object_store_env(&|k| vars.get(k).map(|v| v.to_string())).unwrap();
        assert_eq!(cfg.object_store.backend, "s3");
        assert_eq!(cfg.object_store.s3.bucket, "custom-bucket");
        assert_eq!(cfg.object_store.s3.region, "custom-region");
        assert_eq!(cfg.object_store.s3.presign_ttl_secs, 120);
        let output = toml::to_string(&cfg.redacted()).unwrap();
        assert!(!output.contains("private-access-id"));
        assert!(!output.contains("private-secret-key"));
        cfg.object_store.s3.endpoint = "https://user:password@bucket.example?secret=1".into();
        cfg.object_store.s3.public_base_url = Some("https://cdn.example?secret=2".into());
        assert!(!toml::to_string(&cfg.redacted()).unwrap().contains("secret="));
        assert_eq!(cfg.object_store.s3.access_key_id, "private-access-id");
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn redis_credentials_redact_in_config_and_parse_diagnostics() {
        let mut cfg = Config::default();
        cfg.admission.redis_url =
            Some("redis://synthetic-private-secret@127.0.0.1:6390/?token=synthetic-private-secret".into());
        for output in [format!("{cfg:?}"), toml::to_string(&cfg.redacted()).unwrap()] {
            assert!(!output.contains("synthetic-private-secret"));
        }
        let error = Config::parse(
            "[admission]\nredis_url = 'synthetic-private-secret'\nauth_failure = 'synthetic-private-secret'\n",
        )
        .unwrap_err();
        for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(!output.contains("synthetic-private-secret"));
            assert!(output.contains("admission.auth_failure"));
        }
    }
}

#[cfg(test)]
mod ai_redaction_tests {
    use super::*;

    #[test]
    fn ai_diagnostics_redact_key_endpoint_and_model() {
        let config = Config {
            ai: AiExplainConfig {
                base_url: Some("https://user:synthetic-url-secret@example.com?key=synthetic-query-secret".into()),
                api_key: Some("synthetic-api-secret".into()),
                model: "synthetic-model-secret".into(),
                reasoning_effort: Some(memoswish_content::explain::ReasoningEffort::Low),
                budget: None,
            },
            ..Default::default()
        };
        for diagnostic in [format!("{config:?}"), toml::to_string(&config.redacted()).unwrap()] {
            assert!(!diagnostic.contains("synthetic"));
        }
    }
}

#[cfg(test)]
mod password_config_tests {
    use super::*;
    #[test]
    fn smtp_sentinel_diagnostic_contract_and_explicit_profiles() {
        let sentinel = "synthetic-private-smtp-secret";
        for text in [
            format!("[smtp]\npassword='{sentinel}'\nport='{sentinel}'"),
            format!("[smtp]\nusername={{value='{sentinel}'}}"),
            format!("[smtp]\npassword='{sentinel}',"),
        ] {
            let error = Config::parse(&text).unwrap_err();
            for out in [format!("{error}"), format!("{error:#}"), format!("{error:?}"), format!("{error:#?}")] {
                assert!(!out.contains(sentinel));
            }
            for cause in error.chain() {
                assert!(!cause.to_string().contains(sentinel));
            }
        }
        let config = Config {
            smtp: crate::SmtpConfig {
                host: sentinel.into(),
                username: sentinel.into(),
                password: sentinel.into(),
                from: sentinel.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!format!("{:?}", config.smtp).contains(sentinel));
        assert!(!toml::to_string(&config.redacted()).unwrap().contains(sentinel));
        let error = config.validate().unwrap_err();
        for out in [format!("{error}"), format!("{error:#}"), format!("{error:?}"), format!("{error:#?}")] {
            assert!(!out.contains(sentinel));
        }
        Config::default().validate().unwrap();
        let mut config = Config {
            mode: DeploymentMode::MultiTenant,
            password_profile: crate::PasswordProfile::Enabled,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.password_profile = crate::PasswordProfile::Legacy;
        config.validate().unwrap();
        config.password_profile = crate::PasswordProfile::Disabled;
        config.validate().unwrap();
        config.registration_open = true;
        assert!(config.validate().is_err());
        config.mode = DeploymentMode::SingleUser;
        config.registration_open = false;
        config.password_profile = crate::PasswordProfile::Enabled;
        config.validate().unwrap();
    }
}
