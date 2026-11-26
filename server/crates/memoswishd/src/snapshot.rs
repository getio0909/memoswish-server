//! 冷备份的有效配置封装；不构建 AppState，避免迁移、引导、清理及密钥轮换。

use std::path::Path;

use crate::config::Config;

pub fn write_profile_config(
    mut cfg: Config,
    output: &Path,
    require_oidc_key: bool,
    postgres: bool,
) -> anyhow::Result<()> {
    cfg.validate()?;
    if postgres {
        anyhow::ensure!(cfg!(feature = "postgres"), "snapshot requires the postgres feature");
        anyhow::ensure!(
            cfg.database_url
                .as_deref()
                .is_some_and(|url| url.starts_with("postgres://") || url.starts_with("postgresql://")),
            "snapshot requires a PostgreSQL database URL"
        );
    } else {
        anyhow::ensure!(cfg.database_url.is_none(), "snapshot requires the default data-dir SQLite database");
        anyhow::ensure!(cfg!(feature = "sqlite"), "snapshot requires the sqlite feature");
    }
    anyhow::ensure!(cfg.object_store.backend == "local", "snapshot requires the local asset store");
    // 备份恢复后由 CLI 显式绑定新数据目录；所有密钥均保留有效值，不使用脱敏输出。
    let secret = match &cfg.jwt_secret {
        Some(secret) => secret.clone(),
        None => crate::config::key_file::read(&cfg.data_dir.join("jwt_secret"))?
            .ok_or_else(|| anyhow::anyhow!("snapshot requires an existing readable JWT key"))?,
    };
    anyhow::ensure!(secret.len() >= 32 && secret != "***", "snapshot requires a valid existing JWT key");
    cfg.jwt_secret = Some(secret);
    if cfg.oauth.enabled {
        cfg.oauth.validate()?;
    }
    // 即使暂时关闭登录，也需要保留未完成撤销任务的加密密钥。
    if require_oidc_key
        || cfg.oidc.enabled
        || !cfg.oidc.providers.is_empty()
        || !cfg.oidc.encryption_key.is_empty()
        || !cfg.oidc.encryption_keys.is_empty()
    {
        cfg.oidc.validate()?;
        let valid_key = |key: &str| {
            key.len() == 43
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && b"AEIMQUYcgkosw048".contains(&key.as_bytes()[42])
        };
        if cfg.oidc.encryption_keys.is_empty() {
            anyhow::ensure!(
                valid_key(&cfg.oidc.encryption_key),
                "snapshot requires the existing 32-byte OIDC encryption key"
            );
        } else {
            anyhow::ensure!(
                cfg.oidc.encryption_keys.contains_key(&cfg.oidc.encryption_key_id)
                    && cfg.oidc.encryption_keys.values().all(|k| valid_key(&k.secret)),
                "snapshot requires valid active and retained OIDC encryption keys"
            );
            anyhow::ensure!(
                cfg.oidc.encryption_key.is_empty() || valid_key(&cfg.oidc.encryption_key),
                "snapshot legacy OIDC key is invalid"
            );
        }
    }
    cfg.data_dir = "data".into();
    let text = toml::to_string_pretty(&cfg)?;
    crate::config::key_file::publish(output, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(cfg: Config, output: &Path, require_oidc_key: bool) -> anyhow::Result<()> {
        write_profile_config(cfg, output, require_oidc_key, false)
    }

    #[test]
    fn missing_key_never_generates_or_writes_output() {
        let dir = std::env::temp_dir().join(format!("memoswish-snapshot-{}", memoswish_core::ids::new_id()));
        let output = dir.with_extension("toml");
        let cfg = Config { data_dir: dir.clone(), ..Config::default() };
        assert!(write_config(cfg, &output, false).is_err());
        assert!(!dir.exists());
        assert!(!output.exists());
    }

    #[test]
    fn effective_secrets_roundtrip_and_destination_is_exclusive() {
        let output = std::env::temp_dir().join(format!("memoswish-snapshot-{}.toml", memoswish_core::ids::new_id()));
        let cfg = Config {
            jwt_secret: Some("synthetic-existing-key-with-at-least-32-bytes".into()),
            jwt_keys: std::collections::BTreeMap::from([(
                "old".into(),
                memoswish_auth::token::VerificationKey {
                    secret: "synthetic-retained-key-with-at-least-32-bytes".into(),
                    verify_until: Some(1800000000),
                },
            )]),
            ..Config::default()
        };
        write_config(cfg.clone(), &output, false).unwrap();
        let restored: Config = toml::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(restored.jwt_secret, cfg.jwt_secret);
        assert_eq!(restored.jwt_keys["old"].secret, cfg.jwt_keys["old"].secret);
        assert_eq!(restored.jwt_keys["old"].verify_until, Some(1800000000));
        assert_eq!(restored.data_dir, std::path::PathBuf::from("data"));
        assert!(write_config(cfg, &output, false).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_file(output).unwrap();
    }

    #[test]
    fn remote_backends_and_missing_oidc_key_fail_closed() {
        let output = std::env::temp_dir().join(format!("memoswish-snapshot-{}.toml", memoswish_core::ids::new_id()));
        let cfg =
            Config { jwt_secret: Some("synthetic-existing-key-with-at-least-32-bytes".into()), ..Config::default() };
        let mut remote = cfg.clone();
        remote.database_url = Some("postgres://localhost/example".into());
        assert!(write_config(remote, &output, false).is_err());
        let mut remote = cfg.clone();
        remote.object_store.backend = "s3".into();
        assert!(write_config(remote, &output, false).is_err());
        assert!(write_config(cfg.clone(), &output, true).is_err());
        let mut missing = cfg;
        missing.oidc.enabled = true;
        assert!(write_config(missing, &output, false).is_err());
        assert!(!output.exists());
    }
}
