//! 离线产生轮换配置；原文件与旧密钥保留，输出文件独占创建且权限为 0600。
use crate::config::Config;
use memoswish_auth::token::VerificationKey;
use std::path::Path;

pub fn rotate(mut cfg: Config, id: &str, output: &Path) -> anyhow::Result<()> {
    cfg.validate()?;
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid key id"
    );
    anyhow::ensure!(
        !cfg.jwt_keys.contains_key(id) && !cfg.oidc.encryption_keys.contains_key(id),
        "key id already exists"
    );
    // 不生成旧 secret，避免错误配置静默切断未到期的 kid-less 凭据。
    if cfg.jwt_secret.is_none() {
        cfg.jwt_secret = Some(
            crate::config::key_file::read(&cfg.data_dir.join("jwt_secret"))?
                .ok_or_else(|| anyhow::anyhow!("rotation requires an existing JWT key"))?,
        );
    }
    anyhow::ensure!(cfg.jwt_secret.as_ref().is_some_and(|s| s.len() >= 32), "existing JWT secret is invalid");
    cfg.jwt_keys.insert(
        id.into(),
        VerificationKey { secret: memoswish_auth::sessions::generate_encryption_key()?, verify_until: None },
    );
    cfg.jwt_key_id = Some(id.into());
    if !cfg.oidc.encryption_key.is_empty() || !cfg.oidc.encryption_keys.is_empty() {
        if cfg.oidc.encryption_keys.is_empty() {
            let old = if cfg.oidc.encryption_key_id.is_empty() { "legacy" } else { &cfg.oidc.encryption_key_id };
            anyhow::ensure!(old != id, "key id already exists");
            cfg.oidc
                .encryption_keys
                .insert(old.into(), VerificationKey { secret: cfg.oidc.encryption_key.clone(), verify_until: None });
        }
        cfg.oidc.encryption_keys.insert(
            id.into(),
            VerificationKey { secret: memoswish_auth::sessions::generate_encryption_key()?, verify_until: None },
        );
        cfg.oidc.encryption_key_id = id.into();
    }
    let text = toml::to_string_pretty(&cfg)?;
    crate::config::key_file::publish(output, text.as_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_preserves_keys_cutoff_and_refuses_overwrite() {
        let path = std::env::temp_dir().join(format!("memoswish-keys-{}.toml", memoswish_core::ids::new_id()));
        let mut cfg = Config { jwt_secret: Some("s".repeat(32)), ..Config::default() };
        cfg.sessions.legacy_verify_until = Some(1800000000);
        rotate(cfg.clone(), "next", &path).unwrap();
        let next: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(next.jwt_secret, cfg.jwt_secret);
        assert_eq!(next.sessions.legacy_verify_until, Some(1800000000));
        assert_eq!(next.jwt_key_id.as_deref(), Some("next"));
        assert!(rotate(cfg, "next", &path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
