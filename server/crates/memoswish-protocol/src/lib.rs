//! Memoswish 线协议（Wire Protocol）。
//!
//! 本 crate 是前后端、MCP 网关之间唯一的数据契约来源（Single Source of Truth）：
//! - 所有字段统一使用 `snake_case` JSON 命名；
//! - 时间统一使用 RFC 3339（UTC），时长统一使用毫秒整数；
//! - `protocol/schemas/*.schema.json` 由 `memoswishd schema export` 从这里生成，禁止手改。

pub mod learning_controls;
pub use learning_controls::*;
pub mod diagnostics;
pub use diagnostics::*;
pub mod access;
pub use access::*;
pub mod library;
pub use library::*;
pub mod card;
pub mod content_lifecycle;
pub use content_lifecycle::*;
pub mod imports;
pub use imports::*;
pub mod error;
pub mod examples;
pub mod feed;
pub mod feedback;
pub mod lifecycle;
pub mod password_lifecycle;
pub use password_lifecycle::*;
pub mod privacy;
pub use privacy::*;
pub mod server;
pub mod tts;

pub use card::*;
pub use error::*;
pub use feed::*;
pub use feedback::*;
pub use lifecycle::*;
pub use server::*;
pub use tts::*;

/// 当前线协议版本。破坏性变更时递增主版本，并重新生成协议契约。
pub const PROTOCOL_VERSION: &str = "2.22.0";

/// 返回所有对外公开类型的 JSON Schema，键为文件名（不含扩展名）。
pub fn all_schemas() -> Vec<(&'static str, schemars::Schema)> {
    vec![
        ("access-summary", schemars::schema_for!(AccessSummary)),
        ("access-page", schemars::schema_for!(AccessPage)),
        ("speech-diagnostic", schemars::schema_for!(SpeechDiagnostic)),
        ("bgm-clip", schemars::schema_for!(BgmClip)),
        ("card-media", schemars::schema_for!(Card)),
        ("learner-preferences", schemars::schema_for!(LearnerPreferences)),
        ("retention-command", schemars::schema_for!(RetentionCommand)),
        ("card-control-command", schemars::schema_for!(CardControlCommand)),
        ("learner-card-control", schemars::schema_for!(LearnerCardControl)),
        ("hidden-cards-page", schemars::schema_for!(HiddenCardsPage)),
        ("password-verification-request", schemars::schema_for!(PasswordVerificationRequest)),
        ("password-email-request", schemars::schema_for!(PasswordEmailRequest)),
        ("password-challenge-request", schemars::schema_for!(PasswordChallengeRequest)),
        ("password-reset-request", schemars::schema_for!(PasswordResetRequest)),
        ("password-change-request", schemars::schema_for!(PasswordChangeRequest)),
        ("password-request-accepted", schemars::schema_for!(PasswordRequestAccepted)),
        ("password-status", schemars::schema_for!(PasswordStatus)),
        ("diagnostic-report", schemars::schema_for!(DiagnosticReport)),
        ("diagnostic-receipt", schemars::schema_for!(DiagnosticReceipt)),
        ("content-provenance", schemars::schema_for!(ContentProvenance)),
        ("content-metadata", schemars::schema_for!(ContentMetadata)),
        ("card-save", schemars::schema_for!(CardSave)),
        ("publication-command", schemars::schema_for!(PublicationCommand)),
        ("deck-edit", schemars::schema_for!(DeckEdit)),
        ("report-create", schemars::schema_for!(ReportCreate)),
        ("content-report", schemars::schema_for!(ContentReport)),
        ("card-revision", schemars::schema_for!(CardRevision)),
        ("starter-deck", schemars::schema_for!(StarterDeck)),
        ("starter-install", schemars::schema_for!(StarterInstall)),
        ("content-import", schemars::schema_for!(ContentImport)),
        ("content-apkg-import", schemars::schema_for!(ContentApkgImport)),
        ("favorite-command", schemars::schema_for!(FavoriteCommand)),
        ("favorite-state", schemars::schema_for!(FavoriteState)),
        ("library-query", schemars::schema_for!(LibraryQuery)),
        ("library-entry", schemars::schema_for!(LibraryEntry)),
        ("library-page", schemars::schema_for!(LibraryPage)),
        ("review-history-entry", schemars::schema_for!(ReviewHistoryEntry)),
        ("review-history-page", schemars::schema_for!(ReviewHistoryPage)),
        ("feedback-receipt", schemars::schema_for!(FeedbackReceipt)),
        ("privacy-policy", schemars::schema_for!(PrivacyPolicy)),
        ("privacy-record", schemars::schema_for!(PrivacyRecord)),
        ("privacy-state", schemars::schema_for!(PrivacyState)),
        ("privacy-update", schemars::schema_for!(PrivacyUpdate)),
        ("login-request", schemars::schema_for!(LoginRequest)),
        ("register-request", schemars::schema_for!(RegisterRequest)),
        ("explain-request", schemars::schema_for!(ExplainRequest)),
        ("explain-accounting", schemars::schema_for!(ExplainAccounting)),
        ("explain-operation", schemars::schema_for!(ExplainOperation)),
        ("explain-reconcile-request", schemars::schema_for!(ExplainReconcileRequest)),
        ("tts-submission", schemars::schema_for!(TtsSubmission)),
        ("tts-submission-item", schemars::schema_for!(TtsSubmissionItem)),
        ("tts-attachment-receipt", schemars::schema_for!(TtsAttachmentReceipt)),
        ("membership-summary", schemars::schema_for!(MembershipSummary)),
        ("workspace-export", schemars::schema_for!(WorkspaceExport)),
        ("export-asset", schemars::schema_for!(ExportAsset)),
        ("personal-account-export", schemars::schema_for!(PersonalAccountExport)),
        ("personal-workspace-export", schemars::schema_for!(PersonalWorkspaceExport)),
        ("transfer-ownership-request", schemars::schema_for!(TransferOwnershipRequest)),
        ("close-account-request", schemars::schema_for!(CloseAccountRequest)),
        ("workspace-confirmation", schemars::schema_for!(WorkspaceConfirmation)),
        ("session-response", schemars::schema_for!(SessionResponse)),
        ("session-refresh-request", schemars::schema_for!(SessionRefreshRequest)),
        ("session-info", schemars::schema_for!(SessionInfo)),
        ("account-profile", schemars::schema_for!(AccountProfile)),
        ("account-session-response", schemars::schema_for!(AccountSessionResponse)),
        ("workspace-session-request", schemars::schema_for!(WorkspaceSessionRequest)),
        ("account-export", schemars::schema_for!(AccountExport)),
        ("linked-identity", schemars::schema_for!(server::LinkedIdentity)),
        ("card", schemars::schema_for!(card::Card)),
        ("card-draft", schemars::schema_for!(card::CardDraft)),
        ("revision-precondition", schemars::schema_for!(card::RevisionPrecondition)),
        ("deck", schemars::schema_for!(card::Deck)),
        ("deck-import-request", schemars::schema_for!(DeckImportRequest)),
        ("apkg-import-request", schemars::schema_for!(ApkgImportRequest)),
        ("deck-pack", schemars::schema_for!(card::DeckPack)),
        ("portable-deck-pack", schemars::schema_for!(PortableDeckPack)),
        ("portable-media", schemars::schema_for!(PortableMedia)),
        ("portable-import-request", schemars::schema_for!(PortableImportRequest)),
        ("card-explanation", schemars::schema_for!(card::CardExplanation)),
        ("bgm-track", schemars::schema_for!(card::BgmTrack)),
        ("feed-query", schemars::schema_for!(feed::FeedQuery)),
        ("feed-page", schemars::schema_for!(feed::FeedPage)),
        ("learning-stats", schemars::schema_for!(feed::LearningStats)),
        ("prefetch-manifest", schemars::schema_for!(feed::PrefetchManifest)),
        ("feedback-batch", schemars::schema_for!(feedback::FeedbackBatch)),
        ("feedback-ack", schemars::schema_for!(feedback::FeedbackAck)),
        ("server-info", schemars::schema_for!(server::ServerInfo)),
        ("api-error", schemars::schema_for!(error::ApiError)),
        ("oidc-start-request", schemars::schema_for!(server::OidcStartRequest)),
        ("oidc-start-response", schemars::schema_for!(server::OidcStartResponse)),
        ("oidc-complete-request", schemars::schema_for!(server::OidcCompleteRequest)),
        ("oidc-exchange-request", schemars::schema_for!(server::OidcExchangeRequest)),
        ("auth-response", schemars::schema_for!(server::AuthResponse)),
    ]
}

/// 将 JSON Schema 和 fixture 导出到指定目录，返回写入的 JSON 文件数。
pub fn export_contracts(root: &std::path::Path) -> std::io::Result<usize> {
    use std::collections::HashSet;
    use std::fs;

    let schemas = root.join("schemas");
    let fixtures = root.join("fixtures");
    fs::create_dir_all(&schemas)?;
    fs::create_dir_all(&fixtures)?;
    let mut written = HashSet::new();
    let files = all_schemas()
        .into_iter()
        .map(|(name, schema)| (schemas.join(format!("{name}.schema.json")), pretty(&schema)))
        .chain(
            examples::all_fixtures()
                .into_iter()
                .map(|(name, value)| (fixtures.join(format!("{name}.json")), pretty(&value))),
        );
    for (path, contents) in files {
        replace_json(&path, contents.as_bytes())?;
        written.insert(path);
    }
    // 所有文件写入成功后，才清理本次生成清单以外的旧 JSON。
    for dir in [schemas, fixtures] {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") && !written.contains(&path) {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(written.len())
}

// 在目标所在文件系统上完成写入后原子替换，写入失败时保留原文件。
fn replace_json(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::{fs, io::Write};
    for attempt in 0_u64.. {
        let staged = path.with_extension(format!("tmp-{}-{attempt}", std::process::id()));
        let mut file = match fs::File::create_new(&staged) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            result => result?,
        };
        let result = file.write_all(contents);
        drop(file);
        if let Err(error) = result.and_then(|()| fs::rename(&staged, path)) {
            fs::remove_file(staged)?;
            return Err(error);
        }
        return Ok(());
    }
    unreachable!()
}

/// 统一的 JSON 美化输出（两空格缩进 + 末尾换行），保证生成文件稳定可 diff。
pub fn pretty<T: serde::Serialize>(value: &T) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("serializable");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn protocol_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../protocol")
    }

    /// fixture 必须能够无损往返反序列化。
    #[test]
    fn fixtures_roundtrip() {
        let page: FeedPage =
            serde_json::from_value(serde_json::to_value(examples::sample_feed_page()).unwrap()).unwrap();
        assert_eq!(page, examples::sample_feed_page());
        let batch: FeedbackBatch =
            serde_json::from_value(serde_json::to_value(examples::sample_feedback_batch()).unwrap()).unwrap();
        assert_eq!(batch, examples::sample_feedback_batch());
    }

    #[test]
    fn feed_query_preserves_legacy_defaults_and_retry_identity() {
        let legacy: FeedQuery = serde_json::from_value(serde_json::json!({"future": true})).unwrap();
        assert_eq!(legacy, FeedQuery::default());
        assert_eq!(serde_json::to_value(legacy).unwrap(), serde_json::json!({}));
        let query = FeedQuery { request_id: Some("stable-first".into()), ..Default::default() };
        assert_eq!(serde_json::from_value::<FeedQuery>(serde_json::to_value(&query).unwrap()).unwrap(), query);
    }

    #[test]
    fn session_capability_defaults_and_membership_roundtrip() {
        let mut legacy = serde_json::to_value(examples::sample_server_info()).unwrap();
        legacy.as_object_mut().unwrap().remove("opaque_sessions");
        legacy["future_capability"] = serde_json::json!(true);
        assert!(!serde_json::from_value::<ServerInfo>(legacy.clone()).unwrap().opaque_sessions);
        legacy["opaque_sessions"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ServerInfo>(legacy).unwrap().opaque_sessions);
        let summary =
            MembershipSummary { tenant_id: "tenant".into(), name: "Workspace".into(), role: "learner".into() };
        assert_eq!(
            serde_json::from_value::<MembershipSummary>(serde_json::to_value(&summary).unwrap()).unwrap(),
            summary
        );
    }

    /// 仓库中提交的契约文件必须与代码一致；设置 `MEMOSWISH_BLESS=1` 可重新生成。
    #[test]
    fn committed_contracts_are_up_to_date() {
        let dir = protocol_dir();
        if crate::test_environment::var("MEMOSWISH_BLESS").is_ok() {
            export_contracts(&dir).unwrap();
        }
        for (name, schema) in all_schemas() {
            let path = dir.join("schemas").join(format!("{name}.schema.json"));
            let on_disk =
                std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {path:?}; run `make contracts`"));
            assert_eq!(on_disk, pretty(&schema), "{path:?} is stale; run `make contracts`");
        }
        for (name, value) in examples::all_fixtures() {
            let path = dir.join("fixtures").join(format!("{name}.json"));
            let on_disk =
                std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {path:?}; run `make contracts`"));
            assert_eq!(on_disk, pretty(&value), "{path:?} is stale; run `make contracts`");
        }
        // 不允许存在代码中已不再生成的残留文件。
        let expected: std::collections::HashSet<String> = all_schemas()
            .into_iter()
            .map(|(n, _)| format!("schemas/{n}.schema.json"))
            .chain(examples::all_fixtures().into_iter().map(|(n, _)| format!("fixtures/{n}.json")))
            .collect();
        for sub in ["schemas", "fixtures"] {
            for entry in std::fs::read_dir(dir.join(sub)).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                let rel = format!("{sub}/{name}");
                assert!(expected.contains(&rel), "protocol/{rel} is no longer generated; run `make contracts`");
            }
        }
    }

    #[test]
    fn default_ducking_meets_spec() {
        let d = DuckingParams::default();
        assert!(d.attack_ms <= 150);
        assert!((0.2..=0.3).contains(&d.duck_ratio));
        d.validate().unwrap();
    }
}

#[cfg(test)]
mod test_environment {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/test-environment.rs"));
}
