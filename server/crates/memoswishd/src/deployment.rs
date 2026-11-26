//! 部署配置与权限边界；运行前校验，不依赖宿主自动探测或副本本地密钥。
use crate::Config;
use memoswish_protocol::DeploymentMode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Embedded,
    Horizontal,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    AllInOne,
    Api,
    Worker,
    Maintenance,
    Migrator,
}

impl Role {
    pub fn serves(self) -> bool {
        matches!(self, Self::AllInOne | Self::Api)
    }
    pub fn executes(self) -> bool {
        matches!(self, Self::AllInOne | Self::Worker)
    }
    pub fn maintains(self) -> bool {
        matches!(self, Self::AllInOne | Self::Maintenance)
    }
}

impl Config {
    /// CLI 覆盖后和任何安装写入前都必须校验。
    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_runtime_values()?;
        memoswish_core::privacy::validate_policy(&self.privacy)?;
        anyhow::ensure!(
            !self.privacy.hosted || self.mode == DeploymentMode::MultiTenant,
            "hosted privacy enforcement requires authenticated multi-tenant mode"
        );
        anyhow::ensure!(
            matches!(self.default_plan.as_str(), "free" | "pro" | "team" | "self_hosted"),
            "unknown default plan"
        );
        anyhow::ensure!(self.db_max_connections != Some(0), "db_max_connections must be positive");
        self.smtp.validate()?;
        if self.mode == DeploymentMode::MultiTenant
            && self.password_profile == crate::password_mail::PasswordProfile::Enabled
        {
            anyhow::ensure!(
                self.smtp.configured(),
                "enabled password profile requires SMTP; use legacy for deliberate transition or disabled for OIDC-only"
            );
        }
        anyhow::ensure!(
            self.password_profile != crate::password_mail::PasswordProfile::Disabled || !self.registration_open,
            "disabled password profile requires registration_open=false"
        );
        self.sessions.validate()?;
        self.diagnostic_forwarding.validate(&self.privacy)?;
        self.password_work.validate()?;
        anyhow::ensure!(
            self.password_work.workers >= 2,
            "password work requires at least two workers for source isolation"
        );
        self.proxy_trust.validate()?;
        crate::auth_defenses::AuthAdmission::build(&self.admission)?;
        anyhow::ensure!((1..=100).contains(&self.import_staging_limit), "import staging limit must be 1..=100");
        let db = memoswish_storage::DatabaseKind::from_url(&self.database_url())
            .map_err(|_| anyhow::anyhow!("unsupported database URL"))?;
        anyhow::ensure!(
            match db {
                memoswish_storage::DatabaseKind::Sqlite => cfg!(feature = "sqlite"),
                memoswish_storage::DatabaseKind::Postgres => cfg!(feature = "postgres"),
            },
            "database backend requires an unavailable feature"
        );
        // 构造不会发出外部请求，并验证所选后端与编译特性。
        crate::app::build_object_store(self)?;
        crate::admission::build(
            &self.admission,
            "validation",
            self.mcp.rate_limit_burst,
            self.mcp.rate_limit_per_sec,
            self.admission.work_failure,
        )?;
        if self.oidc.enabled {
            anyhow::ensure!(
                cfg!(feature = "oidc") && self.mode == DeploymentMode::MultiTenant,
                "OIDC requires oidc feature and multi_tenant mode"
            );
            self.oidc.validate()?;
        }
        if self.oauth.enabled {
            anyhow::ensure!(
                cfg!(feature = "mcp-oauth") && self.mode == DeploymentMode::MultiTenant && self.mcp.http_enabled,
                "OAuth requires mcp-oauth feature, multi_tenant mode and MCP HTTP"
            );
            self.oauth.validate()?;
        }
        if let Some(secret) = &self.jwt_secret {
            anyhow::ensure!(secret.trim().len() >= 32, "jwt_secret must be at least 32 bytes");
        }
        // 复用认证实现验证 key ring，不能在迁移或 bootstrap 后才发现有效密钥配置错误。
        memoswish_auth::token::JwtCodec::new(
            self.jwt_secret.as_deref().unwrap_or("validation-only-placeholder-32-bytes").as_bytes(),
            self.jwt_ttl_secs,
        )?
        .with_keys(self.jwt_key_id.as_deref(), self.jwt_keys.clone(), self.jwt_legacy_key_until)?;
        #[cfg(feature = "oidc")]
        if self.oidc.enabled {
            let active = if self.oidc.encryption_key_id.is_empty() { "legacy" } else { &self.oidc.encryption_key_id };
            let mut keys = self.oidc.encryption_keys.clone();
            if keys.is_empty() {
                keys.insert(
                    active.into(),
                    memoswish_auth::token::VerificationKey {
                        secret: self.oidc.encryption_key.clone(),
                        verify_until: None,
                    },
                );
            }
            memoswish_auth::keys::EnvelopeKeys::new(
                active,
                &keys,
                (!self.oidc.encryption_key.is_empty()).then_some(self.oidc.encryption_key.as_str()),
                self.oidc.legacy_encryption_until,
            )?;
        }
        if self.profile == Profile::Embedded {
            anyhow::ensure!(self.role == Role::AllInOne, "embedded profile requires all_in_one role");
            return Ok(());
        }
        anyhow::ensure!(
            !self.object_store.s3.access_key_id.trim().is_empty()
                && !self.object_store.s3.secret_access_key.trim().is_empty(),
            "horizontal storage requires explicit credentials"
        );
        anyhow::ensure!(self.role != Role::AllInOne, "horizontal profile requires an explicit role");
        anyhow::ensure!(
            db == memoswish_storage::DatabaseKind::Postgres,
            "horizontal profile requires explicit PostgreSQL"
        );
        anyhow::ensure!(self.mode == DeploymentMode::MultiTenant, "horizontal profile requires multi_tenant mode");
        anyhow::ensure!(
            self.object_store.backend == "s3" && self.object_store.s3.public_base_url.is_none(),
            "horizontal profile requires shared private S3 storage"
        );
        anyhow::ensure!(
            self.jwt_secret.as_ref().is_some_and(|s| s.trim().len() >= 32),
            "horizontal profile requires an explicit shared jwt_secret"
        );
        anyhow::ensure!(
            !self.seed_demo && !self.tts.auto_detect_espeak,
            "horizontal profile forbids demo seeding and host engine auto-detection"
        );
        anyhow::ensure!(
            self.admission.backend == "redis",
            "horizontal profile requires explicit shared Redis admission"
        );
        let mut ids = std::collections::HashSet::from(["unconfigured", "placeholder"]);
        for id in self.tts.commands.iter().map(|c| c.id.as_str()).chain(self.tts.http.iter().map(|c| c.id.as_str())) {
            anyhow::ensure!(!id.is_empty() && ids.insert(id), "invalid or duplicate TTS engine ID");
        }
        anyhow::ensure!(ids.contains(self.tts.default_engine.as_str()), "configured TTS engine is unavailable");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_defaults_and_invalid_roles_fail_before_installation_writes() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
        for (profile, role) in
            [(Profile::Embedded, Role::Worker), (Profile::Horizontal, Role::AllInOne), (Profile::Horizontal, Role::Api)]
        {
            let cfg = Config { profile, role, ..Default::default() };
            assert!(cfg.validate().is_err());
        }
        let cfg = Config { default_plan: "unknown".into(), ..Default::default() };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn embedded_proxy_trust_is_validated_before_profile_return() {
        let mut cfg = Config::default();
        cfg.proxy_trust.trusted_peers = vec!["127.0.0.1".parse().unwrap()];
        assert!(cfg.validate().is_err());
        cfg.proxy_trust.normalized_header = Some("x-real-ip".into());
        cfg.validate().unwrap();
        cfg.proxy_trust.normalized_header = Some("x-forwarded-for".into());
        assert!(cfg.validate().is_err());
    }

    #[tokio::test]
    async fn password_and_diagnostics_are_validated_together_before_startup_effects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = Config {
            mode: DeploymentMode::MultiTenant,
            password_profile: crate::PasswordProfile::Enabled,
            smtp: crate::SmtpConfig {
                host: "localhost".into(),
                port: listener.local_addr().unwrap().port(),
                from: "sender@example.invalid".into(),
                ..Default::default()
            },
            diagnostic_forwarding: crate::DiagnosticForwardingConfig {
                enabled: true,
                endpoint: "https://localhost/api/1/envelope/".into(),
                public_key: "public123".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let version = cfg.diagnostic_forwarding.recipient_version();
        cfg.diagnostic_forwarding.purpose_version = version.clone();
        cfg.privacy.purpose_versions.insert("diagnostics".into(), version);
        cfg.validate().unwrap();
        let invalid: [fn(&mut Config); 3] = [
            |c| c.smtp.port = 0,
            |c| c.password_work.workers = 1,
            |c| c.diagnostic_forwarding.purpose_version = "stale-recipient".into(),
        ];
        for mutate in invalid {
            let directory =
                std::env::temp_dir().join(format!("s29b-password-config-{}", memoswish_core::ids::new_id()));
            let mut rejected = cfg.clone();
            rejected.data_dir = directory.clone();
            mutate(&mut rejected);
            assert!(crate::Daemon::start(rejected).await.is_err());
            assert!(!directory.exists(), "configuration validation must precede installation writes");
        }
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept()).await.is_err());
    }

    #[tokio::test]
    async fn invalid_effective_config_does_not_create_data_dir_or_key() {
        let path = std::env::temp_dir().join(format!("s26a-invalid-{}", memoswish_core::ids::new_id()));
        let cfg =
            Config { data_dir: path.clone(), profile: Profile::Horizontal, role: Role::Api, ..Default::default() };
        assert!(crate::Daemon::start(cfg).await.is_err());
        assert!(!path.exists());
        for policy in [
            memoswish_protocol::PrivacyPolicy { hosted: true, ..Default::default() },
            memoswish_protocol::examples::sample_privacy_policy(),
        ] {
            let cfg = Config { data_dir: path.clone(), privacy: policy, ..Default::default() };
            assert!(crate::Daemon::start(cfg).await.is_err());
            assert!(!path.exists(), "privacy validation must precede installation writes");
        }
    }
}

/// 宿主设置 tracing 时复用此过滤器；传输库即使 trace 级别也不能记录签名 URL/凭据。
pub fn diagnostic_target_allowed(target: &str) -> bool {
    memoswish_mcp::protocol::diagnostic_target_allowed(target)
        && !["reqwest", "hyper", "hyper_util", "h2", "rustls", "sqlx_postgres::options"]
            .iter()
            .any(|prefix| target == *prefix || target.starts_with(&format!("{prefix}::")))
}

#[cfg(all(test, feature = "postgres", feature = "s3", feature = "redis"))]
mod validation_tests {
    use super::*;

    fn valid() -> Config {
        let mut c = Config {
            profile: Profile::Horizontal,
            role: Role::Api,
            mode: DeploymentMode::MultiTenant,
            database_url: Some("postgres://localhost/deployment".into()),
            jwt_secret: Some("shared-test-secret-with-32-bytes-minimum".into()),
            seed_demo: false,
            ..Default::default()
        };
        c.tts.auto_detect_espeak = false;
        c.object_store.backend = "s3".into();
        c.object_store.s3.access_key_id = "test-key".into();
        c.object_store.s3.secret_access_key = "test-secret".into();
        c.admission.backend = "redis".into();
        c.admission.redis_url = Some("redis://127.0.0.1:6393".into());
        c
    }
    #[test]
    fn horizontal_prerequisites_and_each_role_are_explicit() {
        for role in [Role::Api, Role::Worker, Role::Maintenance, Role::Migrator] {
            let mut c = valid();
            c.role = role;
            c.validate().unwrap();
        }
        let invalid: Vec<fn(&mut Config)> = vec![
            |c| c.database_url = None,
            |c| c.database_url = Some("sqlite::memory:".into()),
            |c| c.mode = DeploymentMode::SingleUser,
            |c| c.object_store.backend = "local".into(),
            |c| c.object_store.s3.public_base_url = Some("https://public.example".into()),
            |c| c.object_store.s3.secret_access_key.clear(),
            |c| c.jwt_secret = None,
            |c| c.jwt_secret = Some("".into()),
            |c| c.admission.backend = "memory".into(),
            |c| c.admission.redis_url = None,
            |c| c.seed_demo = true,
            |c| c.tts.auto_detect_espeak = true,
            |c| c.tts.default_engine = "unavailable".into(),
            |c| c.default_plan = "unknown".into(),
        ];
        for mutate in invalid {
            let mut c = valid();
            mutate(&mut c);
            assert!(c.validate().is_err());
        }
    }

    #[test]
    fn horizontal_roles_validate_proxy_trust_and_shared_authentication_admission_together() {
        let invalid: Vec<fn(&mut Config)> = vec![
            |c| c.proxy_trust.trusted_peers.clear(),
            |c| c.proxy_trust.normalized_header = None,
            |c| c.proxy_trust.normalized_header = Some("x-forwarded-for".into()),
            |c| c.admission.auth_failure = memoswish_core::rate_limit::FailureMode::Open,
            |c| c.admission.max_keys = 4095,
            |c| c.admission.backend = "memory".into(),
            |c| c.password_work.workers = 1,
            |c| c.role = Role::AllInOne,
        ];
        for role in [Role::Api, Role::Worker, Role::Maintenance, Role::Migrator] {
            let mut c = valid();
            c.role = role;
            c.proxy_trust.trusted_peers = vec!["127.0.0.1".parse().unwrap()];
            c.proxy_trust.normalized_header = Some("x-learntok-client-ip".into());
            c.validate().unwrap();
            for mutate in &invalid {
                let mut rejected = c.clone();
                mutate(&mut rejected);
                assert!(rejected.validate().is_err(), "role {role:?}");
            }
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::{Layer, layer::SubscriberExt};
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn maximum_logging_cannot_expose_transport_signatures() {
        let buffer = Capture(Default::default());
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new("trace")).with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(tracing_subscriber::filter::filter_fn(|m| diagnostic_target_allowed(m.target()))),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(target:"reqwest::async_impl::client",url="SYNTHETIC_SIGNED_URL","Request");
            tracing::trace!(target:"hyper::proto",headers="SYNTHETIC_SIGNED_URL","Headers");
            tracing::trace!(target:"rmcp::service",payload="SYNTHETIC_SIGNED_URL","Payload");
            tracing::info!(target: "memoswish::deployment", "Safe deployment diagnostic");
        });
        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("Safe deployment diagnostic"));
        assert!(!logs.contains("SYNTHETIC_SIGNED_URL"));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_native_parser_diagnostics_are_filtered_at_default_and_trace_levels() {
        for level in ["info,sqlx=warn,tower_http=info", "trace"] {
            let buffer = Capture(Default::default());
            let writer = buffer.clone();
            let subscriber = tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new(level)).with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .with_filter(tracing_subscriber::filter::filter_fn(|m| diagnostic_target_allowed(m.target()))),
            );
            tracing::subscriber::with_default(subscriber, || {
                // 直接触发上游真实 WARN，验证后续连接解析的防线，不以合成 tracing 事件代替。
                "postgres://user:synthetic@localhost/db?S26B_PARAMETER_SENTINEL=S26B_CREDENTIAL_SENTINEL"
                    .parse::<sqlx::postgres::PgConnectOptions>()
                    .unwrap();
                tracing::info!(target: "memoswish::deployment", "Safe database diagnostic");
            });
            let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
            assert!(logs.contains("Safe database diagnostic"));
            assert!(!logs.contains("S26B_PARAMETER_SENTINEL"));
            assert!(!logs.contains("S26B_CREDENTIAL_SENTINEL"));
        }
    }
}

#[cfg(test)]
mod horizontal_feature_matrix {
    use super::*;
    #[test]
    fn horizontal_requires_all_three_storage_and_admission_features() {
        let mut cfg = Config {
            profile: Profile::Horizontal,
            role: Role::Api,
            mode: DeploymentMode::MultiTenant,
            database_url: Some("postgres://localhost/horizontal".into()),
            jwt_secret: Some("x".repeat(32)),
            seed_demo: false,
            ..Default::default()
        };
        cfg.tts.auto_detect_espeak = false;
        cfg.object_store.backend = "s3".into();
        cfg.object_store.s3.endpoint = "http://127.0.0.1:9000".into();
        cfg.object_store.s3.bucket = "learntok".into();
        cfg.object_store.s3.access_key_id = "synthetic".into();
        cfg.object_store.s3.secret_access_key = "synthetic".into();
        cfg.admission.backend = "redis".into();
        cfg.admission.redis_url = Some("redis://127.0.0.1:6399".into());
        assert_eq!(cfg.validate().is_ok(), cfg!(all(feature = "postgres", feature = "s3", feature = "redis")));
    }
}
