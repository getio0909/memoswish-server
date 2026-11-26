//! 组装服务：数据库 → 对象存储 → 认证 → 内容 / 媒体 / 信息流 → MCP。

use std::sync::Arc;

use anyhow::Context;
use memoswish_application::Services;
use memoswish_auth::{AuthConfig, AuthService, QuotaPolicy, Unlimited};
use memoswish_content::ContentService;
use memoswish_core::repo::Repository;
use memoswish_core::store::ObjectStore;
use memoswish_core::tts::TtsEngine;
use memoswish_feed::FeedService;
use memoswish_mcp::McpServer;
use memoswish_media::MediaService;
use memoswish_media::tts::command::CommandTts;
use memoswish_media::tts::http::HttpTts;
use memoswish_media::tts::placeholder::PlaceholderTts;
use memoswish_protocol::{DeploymentMode, PROTOCOL_VERSION, ServerInfo};
use memoswish_storage::LocalDiskStore;

use crate::config::Config;

/// 运行期共享状态。
#[derive(Clone)]
pub struct AppState {
    pub password_mail: Option<Arc<crate::password_mail::SmtpMail>>,
    pub services: Services,
    pub(crate) health: crate::health::Health,
    #[cfg(feature = "mcp-oauth")]
    pub oauth: Option<Arc<memoswish_auth::oauth::OAuthService>>,
    #[cfg(feature = "oidc")]
    pub oidc: Option<Arc<memoswish_auth::oidc::OidcService>>,
    pub mcp: Arc<McpServer>,
    pub store: Arc<dyn ObjectStore>,
    pub put_tasks: Arc<crate::account::PutTasks>,
    pub repo: Arc<dyn Repository>,
    pub config: Arc<Config>,
    /// HTTP 请求累计计数（供 Prometheus `/metrics` 导出）。
    pub http_requests_total: prometheus::IntCounter,
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    pub auth_admission: Arc<crate::auth_defenses::AuthAdmission>,
    pub auth_limiter: Arc<dyn memoswish_core::rate_limit::RateLimiter>,
}

/// 编译期启用的特性。
pub fn compiled_features() -> Vec<String> {
    let mut f = vec!["personal-library-v1".to_string()];
    if cfg!(feature = "self-hosted") {
        f.push("self-hosted".to_string());
    }
    if cfg!(feature = "commercial-saas") {
        f.push("commercial-saas".to_string());
    }
    for (enabled, name) in [
        (cfg!(feature = "mcp-oauth"), "mcp-oauth"),
        (cfg!(feature = "oidc"), "oidc"),
        (cfg!(feature = "commercial-quota"), "commercial-quota"),
    ] {
        if enabled {
            f.push(name.to_string());
        }
    }
    if cfg!(feature = "sqlite") {
        f.push("sqlite".to_string());
    }
    if cfg!(feature = "s3") {
        f.push("s3".to_string());
    }
    if cfg!(feature = "redis") {
        f.push("redis".to_string());
    }
    if cfg!(feature = "postgres") {
        f.push("postgres".to_string());
    }
    f
}

fn build_quota(cfg: &Config, repo: Arc<dyn Repository>) -> Arc<dyn QuotaPolicy> {
    #[cfg(feature = "commercial-quota")]
    if cfg.mode == DeploymentMode::MultiTenant {
        return Arc::new(memoswish_auth::quota::PlanQuota::new(repo));
    }
    let _ = cfg;
    Arc::new(Unlimited::metered(repo))
}

pub(crate) fn build_object_store(cfg: &Config) -> anyhow::Result<Arc<dyn ObjectStore>> {
    match cfg.object_store.backend.as_str() {
        "local" => Ok(Arc::new(LocalDiskStore::new(cfg.assets_dir(), "/assets"))),
        "s3" => {
            #[cfg(feature = "s3")]
            {
                Ok(Arc::new(memoswish_storage::S3Store::new(cfg.object_store.s3.clone())?))
            }
            #[cfg(not(feature = "s3"))]
            {
                anyhow::bail!("S3 object store requires the s3 feature")
            }
        }
        _ => anyhow::bail!("unknown object store backend"),
    }
}

// 迁移和运行期共用同一配置解析与观察器注入，测试也通过此生产组装入口。
pub(crate) async fn build_repository(
    cfg: &Config,
    migrate: bool,
    observer: Arc<dyn memoswish_core::observability::Observer>,
) -> anyhow::Result<Arc<dyn Repository>> {
    memoswish_storage::connect_observed(&cfg.database_url(), cfg.database_max_connections()?, migrate, observer)
        .await
        .map_err(|_| anyhow::anyhow!("database connection or schema validation failed"))
}

impl AppState {
    /// 内部回归沿用完整启动流程；生产入口必须先取得安装锁。
    #[cfg(test)]
    pub async fn build(cfg: Config) -> anyhow::Result<Self> {
        crate::runtime::build_test_state(cfg).await
    }

    /// 组装服务但不启动恢复或后台 PUT；后续初始化必须由 Daemon 持有。
    #[cfg(test)]
    pub(crate) async fn assemble(cfg: Config) -> anyhow::Result<Self> {
        let health = crate::health::Health::new(&cfg);
        Self::assemble_with_health(cfg, health).await
    }

    pub(crate) async fn assemble_with_health(cfg: Config, health: crate::health::Health) -> anyhow::Result<Self> {
        cfg.validate()?;
        cfg.preflight_key()?;
        let jwt_secret = cfg.resolve_jwt_secret()?;
        let metrics = crate::metrics::Metrics::new(cfg.mode)?;
        let work_limiter = crate::admission::build_observed(
            &cfg.admission,
            "work",
            cfg.mcp.rate_limit_burst,
            cfg.mcp.rate_limit_per_sec,
            cfg.admission.work_failure,
            metrics.clone(),
        )?;
        let auth_admission =
            Arc::new(crate::auth_defenses::AuthAdmission::build_observed(&cfg.admission, metrics.clone())?);
        let auth_limiter = crate::admission::build_observed(
            &cfg.admission,
            "auth",
            60,
            1.0,
            cfg.admission.auth_failure,
            metrics.clone(),
        )?;
        #[cfg(feature = "mcp-oauth")]
        let oauth_limiter = crate::admission::build_observed(
            &cfg.admission,
            "oauth",
            60,
            1.0,
            cfg.admission.oauth_failure,
            metrics.clone(),
        )?;
        #[cfg(feature = "oidc")]
        let oidc_limiter = crate::admission::build_observed(
            &cfg.admission,
            "oidc",
            60,
            1.0,
            cfg.admission.oidc_failure,
            metrics.clone(),
        )?;
        let put_tasks = crate::account::PutTasks::new(&cfg.object_store)?.with_observer(metrics.clone());
        if cfg.oidc.enabled {
            anyhow::ensure!(cfg!(feature = "oidc"), "OIDC requires oidc feature");
            anyhow::ensure!(cfg.mode == DeploymentMode::MultiTenant, "OIDC requires multi_tenant mode");
            cfg.oidc.validate()?;
        }
        if cfg.oauth.enabled {
            anyhow::ensure!(cfg!(feature = "mcp-oauth"), "OAuth requires mcp-oauth feature");
            anyhow::ensure!(
                cfg.mode == DeploymentMode::MultiTenant && cfg.mcp.http_enabled,
                "OAuth requires multi_tenant mode and MCP HTTP"
            );
            cfg.oauth.validate()?;
        }
        if cfg.profile == crate::deployment::Profile::Embedded {
            std::fs::create_dir_all(&cfg.data_dir)
                .with_context(|| format!("cannot create data dir {}", cfg.data_dir.display()))?;
        }
        tracing::info!(target: "memoswish::app", "Connecting configured database");
        let repo = build_repository(
            &cfg,
            cfg.profile == crate::deployment::Profile::Embedded || cfg.role == crate::deployment::Role::Migrator,
            metrics.clone(),
        )
        .await?;
        let store = build_object_store(&cfg)?;
        let store: Arc<dyn ObjectStore> =
            Arc::new(crate::account::TenantStore { inner: store, repo: repo.clone(), tasks: put_tasks.clone() });
        let quota = build_quota(&cfg, repo.clone());

        if cfg.profile == crate::deployment::Profile::Embedded {
            repo.privacy_install_policy(&cfg.privacy).await?;
        }
        if cfg.mode == DeploymentMode::MultiTenant
            && cfg.password_profile == crate::password_mail::PasswordProfile::Legacy
        {
            tracing::warn!(target: "memoswish::app",
                "Legacy password profile preserves login; explicitly configure SMTP and enable password lifecycle or select OIDC-only disabled profile"
            );
        }
        let password_mail = if cfg.mode == DeploymentMode::MultiTenant
            && cfg.password_profile != crate::password_mail::PasswordProfile::Disabled
        {
            crate::password_mail::SmtpMail::build(&cfg.smtp)?
        } else {
            None
        };
        let auth = AuthService::new(
            repo.clone(),
            AuthConfig {
                mode: cfg.mode,
                jwt_secret,
                jwt_ttl_secs: cfg.jwt_ttl_secs,
                registration_open: cfg.registration_open,
                default_plan: cfg.default_plan.clone(),
            },
        )?;
        let auth = auth.with_password_lifecycle(
            cfg.password_profile != crate::password_mail::PasswordProfile::Disabled,
            password_mail.clone().map(|m| m as Arc<dyn memoswish_auth::password_lifecycle::PasswordMail>),
        );
        let auth = auth
            .with_password_config(cfg.password_work.clone())?
            .with_privacy_policy(cfg.privacy.clone())?
            .with_observer(metrics.clone());
        let auth = auth.with_session_config(cfg.sessions.clone())?.with_jwt_keys(
            cfg.jwt_key_id.as_deref(),
            cfg.jwt_keys.clone(),
            cfg.jwt_legacy_key_until,
        )?;
        // 单用户模式以及 CLI 维护操作都依赖本地所有者存在。
        if cfg.profile == crate::deployment::Profile::Embedded {
            auth.bootstrap_local().await?;
        }

        let mut engines: Vec<Arc<dyn TtsEngine>> = vec![Arc::new(memoswish_media::tts::disabled::DisabledTts)];
        if cfg.tts.default_engine == "placeholder" {
            engines.push(Arc::new(PlaceholderTts));
        }
        if cfg.tts.auto_detect_espeak || cfg.tts.default_engine == "espeak-ng" {
            tracing::info!(target: "memoswish::app", "registering configured local speech engine `espeak-ng`");
            engines.push(Arc::new(CommandTts::espeak_ng().with_observer(metrics.clone())));
        }
        for c in &cfg.tts.commands {
            engines.push(Arc::new(CommandTts::new(c.clone()).with_observer(metrics.clone())));
        }
        for h in &cfg.tts.http {
            engines.push(Arc::new(HttpTts::new(h.clone()).with_observer(metrics.clone())));
        }
        metrics.engines.set(engines.len() as i64);
        let default_engine = if engines.iter().any(|e| e.id() == cfg.tts.default_engine) {
            cfg.tts.default_engine.clone()
        } else {
            anyhow::bail!("configured default TTS engine is unavailable");
        };
        let media = MediaService::new(repo.clone(), store.clone(), quota.clone(), engines, &default_engine)?
            .with_privacy_policy(cfg.privacy.clone())
            .with_execution(cfg.role.executes());
        let services = Services {
            operations: Default::default(),
            auth,
            content: ContentService::new(repo.clone())
                .with_observer(metrics.clone())
                .with_import_store(store.clone())
                .with_import_staging_limit(cfg.import_staging_limit)?
                .with_import_execution(cfg.role.executes())
                .with_ai_config(cfg.ai.clone())
                .with_privacy_policy(cfg.privacy.clone())
                .with_external_ai_execution(cfg.role.executes()),
            media,
            feed: FeedService::new(repo.clone(), cfg.feed.clone(), std::sync::Arc::new(chrono::Utc::now))?
                .with_observer(metrics.clone()),
            quota,
            limiter: work_limiter,
        };
        #[cfg(feature = "mcp-oauth")]
        let oauth = if cfg.oauth.enabled {
            let mut service =
                memoswish_auth::oauth::OAuthService::new(repo.clone(), services.auth.clone(), cfg.oauth.clone())?;
            service.limiter = oauth_limiter;
            let service = Arc::new(service);
            if cfg.profile == crate::deployment::Profile::Embedded {
                service.install_clients().await?;
            }
            Some(service)
        } else {
            None
        };
        #[cfg(feature = "oidc")]
        let oidc = if cfg.oidc.enabled {
            Some(Arc::new(
                memoswish_auth::oidc::OidcService::new(
                    cfg.oidc.clone(),
                    repo.clone(),
                    services.auth.clone(),
                    cfg.default_plan.clone(),
                )?
                .with_limiter(oidc_limiter),
            ))
        } else {
            None
        };
        Ok(Self {
            health,
            #[cfg(feature = "oidc")]
            oidc,
            #[cfg(feature = "mcp-oauth")]
            oauth,
            mcp: Arc::new(McpServer::new(services.clone())),
            services,
            store,
            put_tasks,
            repo,
            config: Arc::new(cfg),
            http_requests_total: metrics.http_requests.clone(),
            metrics,
            auth_limiter,
            auth_admission,
            password_mail,
        })
    }

    /// 生命周期所有者建立后才允许内置资产写入和恢复任务启动。
    pub(crate) async fn initialize(&self) -> anyhow::Result<()> {
        crate::metrics::sample(self).await;
        if self.config.profile == crate::deployment::Profile::Horizontal {
            crate::bootstrap::initialize_horizontal(self).await?;
            crate::maintenance_scheduler::initialize(self).await?;
            return Ok(());
        }
        let created = self.services.media.ensure_builtin_bgm().await?;
        if created > 0 {
            tracing::info!(target: "memoswish::app", count = created, "generated builtin bgm tracks");
        }
        if self.config.seed_demo && !self.repo.account_erased_tenant("local").await? {
            crate::seed::seed_if_empty(self).await?;
        }
        crate::maintenance_scheduler::initialize(self).await?;
        Ok(())
    }

    /// `GET /v1/server-info` 内容。
    pub fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "memoswishd".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION.into(),
            mode: self.config.mode,
            features: compiled_features(),
            registration_open: self.services.auth.registration_open(),
            opaque_sessions: true,
            content_lifecycle: Some(true),
            tts_engines: self.services.media.engine_ids(),
            oidc_providers: if self.config.oidc.enabled {
                self.config
                    .oidc
                    .providers
                    .iter()
                    .map(|p| memoswish_protocol::OidcProviderInfo {
                        id: p.id.clone(),
                        name: p.name.clone(),
                        native: !p.native_client_ids.is_empty(),
                    })
                    .collect()
            } else {
                vec![]
            },
        }
    }

    pub fn is_single_user(&self) -> bool {
        self.config.mode == DeploymentMode::SingleUser
    }
}
