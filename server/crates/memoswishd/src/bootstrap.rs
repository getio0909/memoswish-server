//! 显式共享安装初始化；运行角色仅校验已完成的配置身份，不修复 schema 或共享资源。
use crate::{
    Config, Daemon,
    app::AppState,
    deployment::{Profile, Role},
};
use memoswish_core::ids::sha256_hex;

const CONFIG_KEY: &str = "shared/deployment-v1.config.sha256";
const ORIGIN_KEY: &str = "shared/deployment-v2.origin.sha256";
const RATE_KEY: &str = "shared/deployment-v2.admission.sha256";
const IDENTITY_KEY: &str = "shared/deployment-v1.sha256";
const PASSWORD_ORIGIN_KEY: &str = "shared/deployment-v3.password-origin.sha256";
const PASSWORD_KEY: &str = "shared/deployment-v3.password.sha256";

fn identity(cfg: &Config) -> anyhow::Result<String> {
    // 不含角色、监听器、本地目录和数据库凭据；共享权限、密钥、引擎及命名空间必须一致。
    let database =
        url::Url::parse(&cfg.database_url()).map_err(|_| anyhow::anyhow!("invalid deployment database URL"))?;
    let database_options: Vec<_> = database
        .query_pairs()
        .filter(|(key, _)| matches!(key.as_ref(), "options" | "host" | "port" | "dbname"))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let database_identity = (database.host_str(), database.port(), database.path(), database_options);
    let bytes = serde_json::to_vec(&(
        database_identity,
        &cfg.jwt_secret,
        &cfg.jwt_key_id,
        &cfg.jwt_keys,
        cfg.jwt_legacy_key_until,
        &cfg.sessions,
        &cfg.oidc,
        &cfg.oauth,
        &cfg.tts,
        &cfg.admission,
        &cfg.object_store.s3.endpoint,
        &cfg.object_store.s3.bucket,
        &cfg.object_store.s3.region,
        &cfg.default_plan,
        cfg.registration_open,
        &cfg.privacy,
    ))
    .map_err(|_| anyhow::anyhow!("cannot encode shared deployment identity"))?;
    Ok(sha256_hex(&bytes))
}

fn rate_identity(cfg: &Config, legacy: &str) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(&(legacy, cfg.mcp.rate_limit_burst, cfg.mcp.rate_limit_per_sec))
        .map_err(|_| anyhow::anyhow!("cannot encode admission identity"))?;
    Ok(sha256_hex(&bytes))
}

fn password_identity(cfg: &Config, rate: &str) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(&(rate, cfg.password_profile, &cfg.smtp))
        .map_err(|_| anyhow::anyhow!("cannot encode password deployment identity"))?;
    Ok(sha256_hex(&bytes))
}

// 运行及单对象维护只核验 migrator 已发布的身份，不修复标记或启动周期工作。
pub(crate) async fn validate_horizontal(
    config: &Config,
    store: &dyn memoswish_core::store::ObjectStore,
) -> anyhow::Result<()> {
    let expected = identity(config)?;
    let rate = rate_identity(config, &expected)?;
    let password = password_identity(config, &rate)?;
    for (key, expected) in
        [(IDENTITY_KEY, &expected), (CONFIG_KEY, &expected), (RATE_KEY, &rate), (PASSWORD_KEY, &password)]
    {
        let marker = store.read_legacy(key, 128).await?;
        anyhow::ensure!(
            marker.is_some_and(|v| v.bytes == expected.as_bytes()),
            "shared deployment identity is incomplete or mismatched; run migrator"
        );
    }
    for (key, expected) in [(ORIGIN_KEY, &rate), (PASSWORD_ORIGIN_KEY, &password)] {
        if let Some(marker) = store.read_legacy(key, 128).await? {
            anyhow::ensure!(marker.bytes == expected.as_bytes(), "shared deployment origin configuration mismatch");
        }
    }
    Ok(())
}

pub(crate) async fn initialize_horizontal(state: &AppState) -> anyhow::Result<()> {
    #[cfg(feature = "postgres")]
    let _bootstrap_lock = if state.config.role == Role::Migrator {
        Some(memoswish_storage::lock_bootstrap(&state.config.database_url()).await?)
    } else {
        None
    };
    let expected = identity(&state.config)?;
    let existing = state.store.read_legacy(IDENTITY_KEY, 128).await?;
    if let Some(existing) = &existing {
        anyhow::ensure!(existing.bytes == expected.as_bytes(), "shared deployment configuration mismatch");
    }
    let rate_identity = rate_identity(&state.config, &expected)?;
    let config = state.store.read_legacy(CONFIG_KEY, 128).await?;
    if let Some(config) = &config {
        anyhow::ensure!(
            config.bytes == expected.as_bytes(),
            "shared deployment configuration mismatch before bootstrap"
        );
    }
    // 新安装在 v1 config 前固定来源及完整身份；取消后仍能区分新版自定义额度与旧版半成品。
    let origin = state.store.read_legacy(ORIGIN_KEY, 128).await?;
    if let Some(origin) = &origin {
        anyhow::ensure!(origin.bytes == rate_identity.as_bytes(), "shared deployment origin configuration mismatch");
    }
    let rate_marker = state.store.read_legacy(RATE_KEY, 128).await?;
    if let Some(marker) = &rate_marker {
        anyhow::ensure!(marker.bytes == rate_identity.as_bytes(), "shared admission configuration mismatch");
    } else if origin.is_none() && (existing.is_some() || config.is_some()) {
        // 旧版完成与部分引导都未记录 MCP 额度，必须在任何发布前限制默认值升级。
        let defaults = crate::McpConfig::default();
        anyhow::ensure!(
            state.config.mcp.rate_limit_burst == defaults.rate_limit_burst
                && state.config.mcp.rate_limit_per_sec == defaults.rate_limit_per_sec,
            "legacy deployment requires default MCP limits for fingerprint upgrade"
        );
    }
    // 新字段独立加层，不改写既有 v1/v2 字节；旧安装只能以旧行为默认值升级。
    let password_identity = password_identity(&state.config, &rate_identity)?;
    let password_origin = state.store.read_legacy(PASSWORD_ORIGIN_KEY, 128).await?;
    let password_marker = state.store.read_legacy(PASSWORD_KEY, 128).await?;
    for marker in [&password_origin, &password_marker].into_iter().flatten() {
        anyhow::ensure!(marker.bytes == password_identity.as_bytes(), "shared password configuration mismatch");
    }
    if password_origin.is_none()
        && password_marker.is_none()
        && (existing.is_some() || config.is_some() || origin.is_some() || rate_marker.is_some())
    {
        anyhow::ensure!(
            state.config.password_profile == crate::PasswordProfile::Legacy
                && serde_json::to_value(&state.config.smtp)? == serde_json::to_value(crate::SmtpConfig::default())?,
            "legacy deployment requires default password configuration for fingerprint upgrade"
        );
    }
    if state.config.role != Role::Migrator {
        anyhow::ensure!(password_marker.is_some(), "shared password identity is incomplete; run migrator");
        anyhow::ensure!(rate_marker.is_some(), "shared admission identity is incomplete; run migrator");
        anyhow::ensure!(existing.is_some(), "shared deployment bootstrap is incomplete; run migrator");
        anyhow::ensure!(
            config.is_some_and(|v| v.bytes == expected.as_bytes()),
            "shared deployment configuration identity is incomplete"
        );
        return Ok(());
    }
    if password_origin.is_none() && config.is_none() && existing.is_none() && origin.is_none() && rate_marker.is_none()
    {
        // 先记录新版来源，部分 bootstrap 重试仍能证明自定义 SMTP 的原始身份。
        state.store.put_if_absent(PASSWORD_ORIGIN_KEY, password_identity.as_bytes().to_vec(), "text/plain").await?;
        let committed = state.store.read_legacy(PASSWORD_ORIGIN_KEY, 128).await?;
        anyhow::ensure!(
            committed.is_some_and(|v| v.bytes == password_identity.as_bytes()),
            "shared password origin mismatch before bootstrap"
        );
    }
    if origin.is_none() && config.is_none() && existing.is_none() && rate_marker.is_none() {
        // 仅全新安装发布来源；不为旧安装补造新版来源，也不删除中断安装的永久身份。
        state.store.put_if_absent(ORIGIN_KEY, rate_identity.as_bytes().to_vec(), "text/plain").await?;
        let committed_origin = state.store.read_legacy(ORIGIN_KEY, 128).await?;
        anyhow::ensure!(
            committed_origin.is_some_and(|v| v.bytes == rate_identity.as_bytes()),
            "shared deployment origin configuration mismatch before bootstrap"
        );
    }
    // 先固定并核验不可变配置身份，再发布 admission；冲突的旧版恢复不得留下永久 marker。
    if config.is_none() {
        state.store.put_if_absent(CONFIG_KEY, expected.as_bytes().to_vec(), "text/plain").await?;
    }
    let config = state.store.read_legacy(CONFIG_KEY, 128).await?;
    anyhow::ensure!(
        config.is_some_and(|v| v.bytes == expected.as_bytes()),
        "shared deployment configuration mismatch before bootstrap"
    );
    if rate_marker.is_none() {
        state.store.put_if_absent(RATE_KEY, rate_identity.as_bytes().to_vec(), "text/plain").await?;
    }
    let committed_rate = state.store.read_legacy(RATE_KEY, 128).await?;
    anyhow::ensure!(
        committed_rate.is_some_and(|v| v.bytes == rate_identity.as_bytes()),
        "shared admission configuration mismatch before bootstrap"
    );
    if password_marker.is_none() {
        state.store.put_if_absent(PASSWORD_KEY, password_identity.as_bytes().to_vec(), "text/plain").await?;
    }
    let committed_password = state.store.read_legacy(PASSWORD_KEY, 128).await?;
    anyhow::ensure!(
        committed_password.is_some_and(|v| v.bytes == password_identity.as_bytes()),
        "shared password configuration mismatch before bootstrap"
    );
    state.repo.privacy_install_policy(&state.config.privacy).await?;
    state.services.media.ensure_builtin_bgm().await?;
    #[cfg(feature = "mcp-oauth")]
    if let Some(oauth) = &state.oauth {
        oauth.install_clients().await?;
    }
    // 最后发布完成标识；中途失败重试沿用已有对象和客户端，不覆盖不同的安装身份。
    if existing.is_none() {
        state.store.put_if_absent(IDENTITY_KEY, expected.as_bytes().to_vec(), "text/plain").await?;
        let committed = state.store.read_legacy(IDENTITY_KEY, 128).await?;
        anyhow::ensure!(
            committed.is_some_and(|v| v.bytes == expected.as_bytes()),
            "shared deployment configuration mismatch after bootstrap"
        );
    }
    Ok(())
}

/// 使用直连数据库管理凭据执行规范迁移及幂等 bootstrap，完成后退出。
pub async fn migrate(config: Config) -> anyhow::Result<()> {
    migrate_until(config, std::future::pending()).await
}

/// migrator 在初始化阶段响应关闭，未完成 bootstrap 可按严格历史策略重试。
pub async fn migrate_until<F>(mut config: Config, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    anyhow::ensure!(
        config.profile == Profile::Horizontal,
        "explicit migrator requires horizontal profile; embedded installations initialize on startup"
    );
    config.role = Role::Migrator;
    config.validate()?;
    // 复用库生命周期与 PUT 排空，不启动 worker 或 maintenance。
    let daemon = Daemon::start_until(config, shutdown).await?;
    daemon.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    #[test]
    fn password_configuration_changes_v3_without_rewriting_older_identities() {
        let cfg = Config::default();
        let v1 = identity(&cfg).unwrap();
        let v2 = rate_identity(&cfg, &v1).unwrap();
        let v3 = password_identity(&cfg, &v2).unwrap();
        for changed in [
            Config { password_profile: crate::PasswordProfile::Disabled, ..cfg.clone() },
            Config {
                smtp: crate::SmtpConfig { password: "synthetic-secret".into(), ..Default::default() },
                ..cfg.clone()
            },
        ] {
            assert_eq!(identity(&changed).unwrap(), v1);
            assert_eq!(rate_identity(&changed, &v1).unwrap(), v2);
            assert_ne!(password_identity(&changed, &v2).unwrap(), v3);
        }
    }
    #[test]
    fn rate_limits_change_v2_identity_without_rewriting_v1() {
        let cfg = Config::default();
        let v1 = identity(&cfg).unwrap();
        let v2 = rate_identity(&cfg, &v1).unwrap();
        for changed in [
            Config { mcp: crate::McpConfig { rate_limit_burst: 121, ..Default::default() }, ..cfg.clone() },
            Config { mcp: crate::McpConfig { rate_limit_per_sec: 5.0, ..Default::default() }, ..cfg.clone() },
        ] {
            assert_eq!(identity(&changed).unwrap(), v1);
            assert_ne!(rate_identity(&changed, &v1).unwrap(), v2);
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod asset_verification_tests {
    use super::*;
    use memoswish_core::store::ObjectStore;

    #[tokio::test]
    async fn narrow_verification_requires_complete_shared_identity_without_bootstrap() {
        let root = std::env::temp_dir().join(format!("p39-identity-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir_all(root.join("shared")).unwrap();
        let store = memoswish_storage::LocalDiskStore::new(&root, "/assets");
        let config = Config { jwt_secret: Some("k".repeat(32)), ..Default::default() };
        assert!(validate_horizontal(&config, &store).await.is_err());
        assert!(store.read_legacy(CONFIG_KEY, 128).await.unwrap().is_none());
        let expected = identity(&config).unwrap();
        let rate = rate_identity(&config, &expected).unwrap();
        let password = password_identity(&config, &rate).unwrap();
        for (key, bytes) in [(IDENTITY_KEY, &expected), (CONFIG_KEY, &expected), (RATE_KEY, &rate)] {
            store.put(key, bytes.as_bytes().to_vec(), "text/plain").await.unwrap();
        }
        assert!(validate_horizontal(&config, &store).await.is_err());
        assert!(store.read_legacy(PASSWORD_KEY, 128).await.unwrap().is_none());
        store.put(PASSWORD_KEY, password.as_bytes().to_vec(), "text/plain").await.unwrap();
        validate_horizontal(&config, &store).await.unwrap();
        store.put(ORIGIN_KEY, b"wrong-origin".to_vec(), "text/plain").await.unwrap();
        assert!(validate_horizontal(&config, &store).await.is_err());
        assert_eq!(store.read_legacy(ORIGIN_KEY, 128).await.unwrap().unwrap().bytes, b"wrong-origin");
        std::fs::remove_dir_all(root).unwrap();
    }
}
