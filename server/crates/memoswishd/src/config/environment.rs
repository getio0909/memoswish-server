//! 环境消费清单严格区分产品配置和工具变量；错误不回显配置值。
use super::Config;

pub(super) fn reject_legacy_names(keys: impl IntoIterator<Item = std::ffi::OsString>) -> anyhow::Result<()> {
    for key in keys {
        let key = key.to_string_lossy();
        if let Some(suffix) = key.strip_prefix("LEARNTOK_") {
            // 非标准名称可能含控制字符；提示仍保留可执行的前缀迁移规则。
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                anyhow::bail!("legacy environment variable LEARNTOK_{suffix} is unsupported; use MEMOSWISH_{suffix}");
            }
            anyhow::bail!("legacy LEARNTOK_* environment variables are unsupported; use MEMOSWISH_* replacements");
        }
    }
    Ok(())
}

pub(super) fn merge(cfg: &Config, var: &impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
    // 默认与 TOML 已由受保护的解析器解码，config 负责层叠和环境类型转换。
    let mut builder = config::Config::builder()
        .add_source(config::Config::try_from(cfg).map_err(|_| anyhow::anyhow!("cannot encode config"))?);
    for (alias, path, kind) in ALIASES {
        let value = var(alias).or_else(|| (*alias == "MEMOSWISH_DATABASE_URL").then(|| var("DATABASE_URL")).flatten());
        let Some(value) = value else { continue };
        let invalid = || anyhow::anyhow!("invalid environment override: {alias}");
        let value: config::Value = match *kind {
            "bool" => match value.as_str() {
                "1" | "true" | "yes" => true.into(),
                "0" | "false" | "no" => false.into(),
                _ => return Err(invalid()),
            },
            "u64" => value.parse::<u64>().map_err(|_| invalid())?.into(),
            "i64" => value.parse::<i64>().map_err(|_| invalid())?.into(),
            "json" => {
                let json: serde_json::Value = serde_json::from_str(&value).map_err(|_| invalid())?;
                if !json.is_array() {
                    return Err(invalid());
                }
                serde_json::from_value::<config::Value>(json).map_err(|_| invalid())?
            }
            _ => value.into(),
        };
        builder = builder.set_override(*path, value).map_err(|_| invalid())?;
    }
    let effective = builder.build().map_err(|_| anyhow::anyhow!("invalid effective config"))?;
    let mut unknown = false;
    let merged = serde_ignored::deserialize(effective, |_| unknown = true)
        .map_err(|_| anyhow::anyhow!("invalid effective config"))?;
    anyhow::ensure!(!unknown, "environment contains unknown config fields");
    Ok(merged)
}

pub(super) fn merge_current(cfg: &Config) -> anyhow::Result<Config> {
    reject_legacy_names(std::env::vars_os().map(|(key, _)| key))?;
    for (key, value) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MEMOSWISH_") {
            let key = key.to_str().ok_or_else(|| anyhow::anyhow!("non-Unicode product environment name"))?;
            let known = ALIASES.iter().any(|(alias, _, _)| *alias == key);
            anyhow::ensure!(known || TOOL_VARIABLES.contains(&key), "unknown product environment variable");
            anyhow::ensure!(value.to_str().is_some(), "non-Unicode product environment value");
        }
    }
    if std::env::var_os("DATABASE_URL").is_some_and(|v| v.to_str().is_none()) {
        anyhow::bail!("non-Unicode database environment value");
    }
    merge(cfg, &|key| std::env::var(key).ok())
}

// 此清单只登记仓库工具和客户端变量；它们不参与 daemon 配置覆盖。
const TOOL_VARIABLES: &[&str] = &[
    "MEMOSWISH_CONFIG",
    "MEMOSWISH_TOKEN",
    "MEMOSWISH_BLESS",
    "MEMOSWISH_CALLBACK_SCHEME",
    "MEMOSWISH_CLOUD_URL",
    "MEMOSWISH_COMPAT_INVENTORY",
    "MEMOSWISH_COMPAT_INVENTORY_WRITE",
    "MEMOSWISH_COMPAT_REQUESTS",
    "MEMOSWISH_COMPAT_RESPONSES",
    "MEMOSWISH_CORE_REVISION",
    "MEMOSWISH_DISPLAY_NAME",
    "MEMOSWISH_E2E_TOKEN",
    "MEMOSWISH_E2E_URL",
    "MEMOSWISH_E3A_CHILD",
    "MEMOSWISH_E3A_ROOT",
    "MEMOSWISH_E3A_STARTUP_ROOT",
    "MEMOSWISH_EDITION",
    "MEMOSWISH_GENERATED_REFERENCES",
    "MEMOSWISH_HISTORY_ITEMS",
    "MEMOSWISH_LEGACY_VERIFY_UNTIL",
    "MEMOSWISH_NAMESPACE",
    "MEMOSWISH_NEW",
    "MEMOSWISH_PG_FIXTURE_PROBE",
    "MEMOSWISH_RECOVERY_BINARY",
    "MEMOSWISH_S28_LOCK_DRAIN_CHILD",
    "MEMOSWISH_SERVER_URL",
    "MEMOSWISH_TEST_POSTGRES_URL",
    "MEMOSWISH_TEST_REDIS_URL",
    "MEMOSWISH_S26B_CHILD",
];

const ALIASES: &[(&str, &str, &str)] = &[
    ("MEMOSWISH_PASSWORD_PROFILE", "password_profile", "str"),
    ("MEMOSWISH_SMTP_HOST", "smtp.host", "str"),
    ("MEMOSWISH_SMTP_USERNAME", "smtp.username", "str"),
    ("MEMOSWISH_SMTP_PASSWORD", "smtp.password", "str"),
    ("MEMOSWISH_SMTP_FROM", "smtp.from", "str"),
    ("MEMOSWISH_PROFILE", "profile", "str"),
    ("MEMOSWISH_ROLE", "role", "str"),
    ("MEMOSWISH_IMPORT_STAGING_LIMIT", "import_staging_limit", "i64"),
    ("MEMOSWISH_HEALTH_BIND", "health_bind", "str"),
    ("MEMOSWISH_BIND", "bind", "str"),
    ("MEMOSWISH_MODE", "mode", "str"),
    ("MEMOSWISH_DATA_DIR", "data_dir", "str"),
    ("MEMOSWISH_DATABASE_URL", "database_url", "str"),
    ("MEMOSWISH_JWT_SECRET", "jwt_secret", "str"),
    ("MEMOSWISH_REGISTRATION_OPEN", "registration_open", "bool"),
    ("MEMOSWISH_SEED_DEMO", "seed_demo", "bool"),
    ("MEMOSWISH_REDIS_URL", "admission.redis_url", "str"),
    ("MEMOSWISH_ADMISSION_BACKEND", "admission.backend", "str"),
    ("MEMOSWISH_TTS_ENGINE", "tts.default_engine", "str"),
    ("MEMOSWISH_AI_BASE_URL", "ai.base_url", "str"),
    ("MEMOSWISH_AI_API_KEY", "ai.api_key", "str"),
    ("MEMOSWISH_AI_MODEL", "ai.model", "str"),
    ("MEMOSWISH_AI_REASONING_EFFORT", "ai.reasoning_effort", "str"),
    ("MEMOSWISH_OIDC_ENABLED", "oidc.enabled", "bool"),
    ("MEMOSWISH_OIDC_PUBLIC_BASE_URL", "oidc.public_base_url", "str"),
    ("MEMOSWISH_OIDC_ENCRYPTION_KEY", "oidc.encryption_key", "str"),
    ("MEMOSWISH_OIDC_PROVIDERS_JSON", "oidc.providers", "json"),
    ("MEMOSWISH_OIDC_RETURN_URIS_JSON", "oidc.return_uris", "json"),
    ("MEMOSWISH_OAUTH_ENABLED", "oauth.enabled", "bool"),
    ("MEMOSWISH_OAUTH_ISSUER", "oauth.issuer", "str"),
    ("MEMOSWISH_OAUTH_PUBLIC_BASE_URL", "oauth.public_base_url", "str"),
    ("MEMOSWISH_OAUTH_MCP_RESOURCE", "oauth.mcp_resource", "str"),
    ("MEMOSWISH_OAUTH_DYNAMIC_REGISTRATION", "oauth.dynamic_registration", "bool"),
    ("MEMOSWISH_OAUTH_CLIENTS_JSON", "oauth.pre_registered_clients", "json"),
    ("MEMOSWISH_OBJECT_STORE", "object_store.backend", "str"),
    ("MEMOSWISH_S3_ENDPOINT", "object_store.s3.endpoint", "str"),
    ("MEMOSWISH_S3_BUCKET", "object_store.s3.bucket", "str"),
    ("MEMOSWISH_S3_REGION", "object_store.s3.region", "str"),
    ("MEMOSWISH_S3_ACCESS_KEY_ID", "object_store.s3.access_key_id", "str"),
    ("MEMOSWISH_S3_SECRET_ACCESS_KEY", "object_store.s3.secret_access_key", "str"),
    ("MEMOSWISH_S3_PUBLIC_BASE_URL", "object_store.s3.public_base_url", "str"),
    ("MEMOSWISH_S3_PRESIGN_TTL_SECS", "object_store.s3.presign_ttl_secs", "u64"),
    ("MEMOSWISH_CORS_ORIGINS_JSON", "cors_origins", "json"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_aliases_precedence_and_secret_safe_failures() {
        let cfg = Config::parse("bind='file:1'\nseed_demo=true\ncors_origins=['https://file.example']").unwrap();
        let vars = std::collections::HashMap::from([
            ("MEMOSWISH_BIND", "env:2"),
            ("MEMOSWISH_SEED_DEMO", "no"),
            ("MEMOSWISH_OIDC_ENABLED", "yes"),
            ("MEMOSWISH_CORS_ORIGINS_JSON", "[\"https://env.example\"]"),
            ("MEMOSWISH_DATABASE_URL", "postgres://primary/db"),
            ("DATABASE_URL", "postgres://fallback/db"),
            ("MEMOSWISH_IMPORT_STAGING_LIMIT", "7"),
        ]);
        let mut result = merge(&cfg, &|k| vars.get(k).map(|v| v.to_string())).unwrap();
        assert_eq!(result.bind, "env:2");
        assert!(!result.seed_demo);
        assert!(result.oidc.enabled);
        assert_eq!(result.cors_origins, ["https://env.example"]);
        assert_eq!(result.database_url.as_deref(), Some("postgres://primary/db"));
        assert_eq!(result.import_staging_limit, 7);
        result.bind = "cli:3".into();
        assert_eq!(result.bind, "cli:3");
        for alias in [
            "MEMOSWISH_MODE",
            "MEMOSWISH_PROFILE",
            "MEMOSWISH_ROLE",
            "MEMOSWISH_IMPORT_STAGING_LIMIT",
            "MEMOSWISH_SEED_DEMO",
            "MEMOSWISH_S3_PRESIGN_TTL_SECS",
            "MEMOSWISH_OIDC_PROVIDERS_JSON",
        ] {
            let error = merge(&cfg, &|k| (k == alias).then(|| "SYNTHETIC_SECRET".into())).unwrap_err();
            for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
                assert!(!output.contains("SYNTHETIC_SECRET"));
            }
            assert_eq!(error.chain().count(), 1);
        }
        for value in ["", " ", "unknown"] {
            let result = merge(&cfg, &|k| (k == "MEMOSWISH_JWT_SECRET").then(|| value.into())).unwrap();
            assert!(result.validate().is_err());
        }
        let error = merge(&cfg, &|key| {
            (key == "MEMOSWISH_OIDC_PROVIDERS_JSON").then(|| "[{\"unknown_secret_field\":\"SYNTHETIC_SECRET\"}]".into())
        })
        .unwrap_err();
        assert!(!format!("{error:#?}").contains("SYNTHETIC_SECRET"));
        for value in ["0", "-1", "101"] {
            let result = merge(&cfg, &|k| (k == "MEMOSWISH_IMPORT_STAGING_LIMIT").then(|| value.into())).unwrap();
            assert!(result.validate().is_err());
        }
    }

    #[test]
    fn import_config_is_strict_and_validated_before_installation() {
        for limit in [1, 100] {
            let cfg = Config::parse(&format!("import_staging_limit={limit}")).unwrap();
            cfg.validate().unwrap();
        }
        for text in ["import_staging_limt=2", "import_staging_limit='private'", "[retention]\nversion=1"] {
            assert!(Config::parse(text).is_err());
        }
        for limit in [0, -1, 101] {
            assert!(Config::parse(&format!("import_staging_limit={limit}")).unwrap().validate().is_err());
        }
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;

    #[test]
    fn privacy_config_is_strict_validated_and_preserved_by_environment_layering() {
        let cfg = Config {
            mode: memoswish_protocol::DeploymentMode::MultiTenant,
            privacy: memoswish_protocol::examples::sample_privacy_policy(),
            ..Default::default()
        };
        let text = toml::to_string(&cfg).unwrap();
        let parsed = Config::parse(&text).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.privacy, cfg.privacy);
        let layered = merge(&parsed, &|k| (k == "MEMOSWISH_BIND").then(|| "127.0.0.1:9999".into())).unwrap();
        assert_eq!(layered.privacy, cfg.privacy);
        for text in [
            "[privacy]\nhostde=true",
            "[privacy]\nhosted='SYNTHETIC_SECRET'",
            "[privacy]\nallowed_regions='SYNTHETIC_SECRET'",
            "[privacy.purpose_versions]\nSYNTHETIC_SECRET=1",
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(!format!("{error:#?}").contains("SYNTHETIC_SECRET"));
        }
        for text in [
            "[privacy]\nhosted=true",
            "[privacy.purpose_versions]\nunknown='v1'",
            "[privacy.purpose_versions]\nexternal_tts=''",
        ] {
            assert!(Config::parse(text).unwrap().validate().is_err());
        }
    }

    #[test]
    fn arbitrary_key_names_and_unknown_toml_fields_never_echo_values() {
        let error = Config::parse("[jwt_keys.SYNTHETIC_SECRET]\nsecret='valid'\nverify_until='SYNTHETIC_SECRET'\n")
            .unwrap_err();
        for text in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(!text.contains("SYNTHETIC_SECRET"), "{text}");
        }
        let path = std::env::temp_dir().join(format!("s26a-unknown-{}.toml", memoswish_core::ids::new_id()));
        std::fs::write(&path, "bind_typo='SYNTHETIC_SECRET'").unwrap();
        let error = Config::load(Some(&path)).unwrap_err();
        assert!(!format!("{error:#?}").contains("SYNTHETIC_SECRET"));
        std::fs::remove_file(path).unwrap();
    }
}
