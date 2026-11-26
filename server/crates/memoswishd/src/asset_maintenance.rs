//! 单对象验证只打开已有安装，不组装 daemon、迁移、引导或发现恢复工作。

use crate::{Config, deployment::Profile};
use memoswish_auth::{AuthConfig, AuthService};
use memoswish_core::asset_read::ReadManifest;

pub async fn verify_asset(
    config: &Config,
    token: Option<&str>,
    key: &str,
    surface: &str,
    owner: Option<&str>,
    max_blocks: usize,
) -> anyhow::Result<ReadManifest> {
    config.validate()?;
    anyhow::ensure!(config.role.maintains(), "asset verification requires maintenance role or embedded all_in_one");
    config.preflight_key()?;
    memoswish_core::store::validate_key(key)?;
    anyhow::ensure!(matches!(surface, "content" | "feed" | "media"), "invalid asset surface");
    anyhow::ensure!((1..=1024).contains(&max_blocks), "verification block budget must be 1 to 1024");
    // 维护不能生成缺失密钥；已有安装的密钥须在连接数据库前通过安全读取。
    let secret = config.existing_jwt_secret()?;
    if config.profile == Profile::Embedded {
        crate::directory_lock::acquire_existing(&config.data_dir)?;
    }
    let repo = memoswish_storage::open_runtime(&config.database_url(), config.database_max_connections()?).await?;
    let auth = AuthService::new(
        repo.clone(),
        AuthConfig {
            mode: config.mode,
            jwt_secret: secret,
            jwt_ttl_secs: config.jwt_ttl_secs,
            registration_open: config.registration_open,
            default_plan: config.default_plan.clone(),
        },
    )?
    .with_privacy_policy(config.privacy.clone())?
    .with_session_config(config.sessions.clone())?
    .with_jwt_keys(config.jwt_key_id.as_deref(), config.jwt_keys.clone(), config.jwt_legacy_key_until)?;
    let principal = auth.authenticate(token).await?;
    auth.require_privacy_collection(&principal).await?;
    let store = crate::app::build_object_store(config)?;
    if config.profile == Profile::Horizontal {
        crate::bootstrap::validate_horizontal(config, store.as_ref()).await?;
    }
    Ok(memoswish_application::asset_delivery::verify(
        repo.as_ref(),
        store.as_ref(),
        &principal,
        key,
        surface,
        owner,
        max_blocks,
    )
    .await?)
}

#[cfg(all(test, feature = "sqlite", unix))]
mod tests {
    use super::*;
    use memoswish_core::{Principal, tts::SpeechWork};
    use std::{path::Path, process::Command};

    fn dump(root: &Path) -> String {
        let output = Command::new("sqlite3").arg(root.join("learntok.db")).arg(".dump").output().unwrap();
        assert!(output.status.success());
        let dump = String::from_utf8(output.stdout).unwrap();
        assert!(!dump.contains("ERROR:"), "SQLite dump failed");
        dump.lines()
            .filter(|line| {
                !line.starts_with("INSERT INTO asset_read_metadata")
                    && !line.starts_with("INSERT INTO \"asset_read_metadata\"")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn config(root: &Path) -> Config {
        let mut cfg =
            Config { data_dir: root.into(), jwt_secret: Some("k".repeat(32)), seed_demo: false, ..Default::default() };
        cfg.privacy = memoswish_protocol::PrivacyPolicy {
            hosted: false,
            ..memoswish_protocol::examples::sample_privacy_policy()
        };
        cfg.tts.auto_detect_espeak = false;
        cfg.tts.default_engine = "sentinel".into();
        cfg.tts.commands.push(memoswish_media::tts::command::CommandTtsConfig {
            external_transfer: false,
            id: "sentinel".into(),
            program: "touch".into(),
            args: vec![root.join("provider-called").to_string_lossy().into_owned()],
            text_via_stdin: false,
            default_voice: "default".into(),
            timeout_secs: 30,
        });
        cfg
    }

    async fn seed(root: &Path) -> crate::app::AppState {
        use memoswish_core::{
            explanations::{ExplanationAdmission, ExplanationContext},
            imports::ImportAuthority,
        };
        let cfg = config(root);
        // 不运行 initialize；构造上一进程遗留的真实 pending speech/import/explanation。
        let state = crate::app::AppState::assemble(cfg).await.unwrap();
        let command = &state.config.tts.commands[0];
        assert!(
            Command::new(&command.program).args(&command.args).status().expect("Test requires touch on PATH").success()
        );
        std::fs::remove_file(root.join("provider-called")).expect("The touch fixture must create the marker");
        let p = Principal::local_owner("single_user");
        for (kind, version, value) in [
            ("notice", "notice-v1", ""),
            ("terms", "terms-v1", ""),
            ("age", "notice-v1", "example-region"),
            ("external_ai", "provider-policy-v1", ""),
        ] {
            let current = state.services.auth.privacy_state(&p).await.unwrap();
            state
                .services
                .auth
                .update_privacy(
                    &p,
                    &memoswish_protocol::PrivacyUpdate {
                        expected_revision: current.revision,
                        kind: kind.into(),
                        version: version.into(),
                        decision: true,
                        value: value.into(),
                    },
                )
                .await
                .unwrap();
        }
        let deck = memoswish_protocol::examples::sample_deck();
        state.repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
        let asset = state.store.put("tenants/local/imports/verify.png", b"image".to_vec(), "image/png").await.unwrap();
        let mut card = memoswish_protocol::examples::sample_card();
        card.deck_id = deck.id;
        card.tts = None;
        card.bgm = None;
        card.visual.image = Some(asset);
        state.repo.insert_card(&p.tenant_id, &card).await.unwrap();
        let engine = memoswish_media::tts::command::CommandTts::new(command.clone());
        use memoswish_core::tts::TtsEngine;
        state
            .repo
            .accept_speech(
                &p,
                &SpeechWork {
                    provenance: None,
                    privacy: None,
                    engine: engine.id().into(),
                    namespace: engine.cache_namespace(),
                    request: memoswish_core::tts::TtsRequest {
                        text: "pending".into(),
                        language: "en".into(),
                        voice: "default".into(),
                        speed: 1.0,
                    },
                    amount: 7,
                    legacy_output: None,
                },
                None,
                None,
            )
            .await
            .unwrap();
        let work = state
            .services
            .content
            .prepare_deck_pack(&p, memoswish_protocol::examples::sample_deck_pack(), false)
            .unwrap();
        state
            .repo
            .accept_import(
                &ImportAuthority::capture(&p, None),
                "pending-import",
                &memoswish_core::ids::sha256_hex(b"fingerprint"),
                &work,
                None,
                100,
            )
            .await
            .unwrap();
        state
            .repo
            .admit_explanation(
                &p,
                &ExplanationAdmission {
                    context: ExplanationContext {
                        locale: "en".into(),
                        model_profile: "test".into(),
                        prompt_version: "v1".into(),
                        policy_version: "v1".into(),
                    },
                    request_id: "pending-explanation".into(),
                    command_hash: memoswish_core::ids::sha256_hex(b"explain"),
                    card_id: card.id,
                    revision: card.revision,
                    cache_key: None,
                    profile_id: memoswish_core::ids::sha256_hex(b"profile"),
                    policy: Some(crate::tests::explanation_test_policy()),
                },
            )
            .await
            .unwrap();
        assert!(!root.join("provider-called").exists());
        state
    }

    #[test]
    fn single_object_entry_leaves_pending_work_untouched() {
        if let Ok(root) = crate::test_environment::var("MEMOSWISH_ASSET_VERIFY_CHILD") {
            let root = Path::new(&root);
            let cfg = config(root);
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
                let invalid = crate::test_environment::var("MEMOSWISH_ASSET_VERIFY_CASE").unwrap();
                let result = verify_asset(
                    &cfg,
                    (invalid == "credential").then_some("invalid"),
                    if invalid == "key" { "../invalid" } else { "tenants/local/imports/verify.png" },
                    "content",
                    Some(&memoswish_protocol::examples::sample_card().id),
                    1024,
                )
                .await;
                if invalid == "valid" {
                    assert!(result.unwrap().verified);
                } else {
                    assert!(result.is_err());
                }
            });
            return;
        }
        let root = std::env::temp_dir().join(format!("p39-maintenance-{}", memoswish_core::ids::new_id()));
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            // 保持夹具池存活，避免 .dump 与运行时关闭时的 WAL checkpoint 竞争。
            let state = seed(&root).await;
            let before = dump(&root);
            for case in ["credential", "key", "valid"] {
                let output = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "asset_maintenance::tests::single_object_entry_leaves_pending_work_untouched",
                        "--nocapture",
                    ])
                    .env("MEMOSWISH_ASSET_VERIFY_CHILD", &root)
                    .env("MEMOSWISH_ASSET_VERIFY_CASE", case)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{case}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    dump(&root),
                    before,
                    "no recovery claims, provider attempts, bootstrap or unrelated cleanup: {case}"
                );
                assert!(!root.join("provider-called").exists());
            }
            drop(state);
            tokio::task::yield_now().await;
        });
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn invalid_role_config_or_key_cannot_open_or_create_installation() {
        let root = std::env::temp_dir().join(format!("p39-maintenance-invalid-{}", memoswish_core::ids::new_id()));
        let base = Config { data_dir: root.clone(), ..Default::default() };
        for cfg in [
            Config { role: crate::deployment::Role::Worker, ..base.clone() },
            Config { jwt_secret: Some("short".into()), ..base.clone() },
            base,
        ] {
            assert!(verify_asset(&cfg, None, "tenants/local/x", "content", None, 1).await.is_err());
            assert!(!root.exists(), "maintenance must not initialize an installation or key");
        }
    }
}
