//! 当前契约的类型往返、递归 Schema 与失败边界。
use std::collections::{BTreeMap, BTreeSet};

use memoswish_protocol::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

struct NoExternal;
impl jsonschema::Retrieve for NoExternal {
    fn retrieve(&self, _: &jsonschema::Uri<String>) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("external schema references are forbidden".into())
    }
}

fn validator(schema: &Value) -> Result<jsonschema::Validator, jsonschema::ValidationError<'static>> {
    jsonschema::draft202012::options().should_validate_formats(true).with_retriever(NoExternal).build(schema)
}

fn roundtrip<T: Serialize + DeserializeOwned>(raw: Value) {
    let value: T = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(serde_json::to_value(value).unwrap(), raw);
}

#[test]
fn retention_command_preserves_absent_null_and_value() {
    let schema = serde_json::to_value(schemars::schema_for!(RetentionCommand)).unwrap();
    let check = validator(&schema).unwrap();
    for raw in [
        json!({"expected_revision": 3}),
        json!({"expected_revision": 3, "desired_retention": null}),
        json!({"expected_revision": 3, "desired_retention": 0.85}),
    ] {
        check.validate(&raw).unwrap();
        roundtrip::<RetentionCommand>(raw);
    }
}

#[test]
fn learning_control_optional_fields_preserve_absent_and_present_identity() {
    roundtrip::<LearnerPreferences>(json!({"revision":0,"effective_retention":0.9}));
    roundtrip::<LearnerCardControl>(json!({"card_id":"card","revision":0,"suspended":false}));
    roundtrip::<HiddenCardsPage>(json!({"items":[]}));
    roundtrip::<HiddenCardsPage>(json!({"items":[],"next_after":"card"}));
    let fixtures: BTreeMap<_, _> = examples::all_fixtures().into_iter().collect();
    for present in [false, true] {
        let mut library = fixtures["library-entry"].clone();
        let mut history = fixtures["review-history-entry"].clone();
        if present {
            library["control"] = fixtures["learner-card-control"].clone();
            history["control"] = fixtures["learner-card-control"].clone();
        }
        roundtrip::<LibraryEntry>(library);
        roundtrip::<ReviewHistoryEntry>(history);
    }
}

#[test]
fn compatibility_lifecycle_extensions_preserve_missing_null_and_explicit_defaults() {
    fn check<T: Serialize + DeserializeOwned + schemars::JsonSchema>(mut raw: Value, field: &str, values: &[Value]) {
        raw.as_object_mut().unwrap().remove(field);
        let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
        let check = validator(&schema).unwrap();
        for value in [None, Some(Value::Null)].into_iter().chain(values.iter().cloned().map(Some)) {
            let mut input = raw.clone();
            if let Some(value) = &value {
                input[field] = value.clone();
            }
            assert!(check.is_valid(&input), "{field}: {input}");
            let decoded: T = serde_json::from_value(input.clone()).unwrap();
            let output = serde_json::to_value(decoded).unwrap();
            if value.is_none() || value == Some(Value::Null) {
                assert_eq!(output, raw);
            } else {
                assert_eq!(output, input);
            }
        }
    }
    check::<Deck>(serde_json::to_value(examples::sample_deck()).unwrap(), "revision", &[json!(0), json!(1), json!(7)]);
    check::<ServerInfo>(
        serde_json::to_value(examples::sample_server_info()).unwrap(),
        "content_lifecycle",
        &[json!(false), json!(true)],
    );
}

#[test]
fn compatibility_all_current_fixtures_have_typed_roundtrip_and_recursive_schema() {
    let fixtures: BTreeMap<_, _> = examples::all_fixtures().into_iter().collect();
    assert_eq!(fixtures.len(), examples::all_fixtures().len(), "duplicate fixture identifier");
    let schemas: BTreeMap<_, _> =
        all_schemas().into_iter().map(|(n, s)| (n, serde_json::to_value(s).unwrap())).collect();
    assert_eq!(schemas.len(), all_schemas().len(), "duplicate schema identifier");
    let mut covered = BTreeSet::new();
    macro_rules! cases {
        ($($ty:ty => $name:literal),* $(,)?) => { $(
            assert!(covered.insert($name), "duplicate codec identifier");
            let raw = fixtures[$name].clone();
            roundtrip::<$ty>(raw.clone());
            let schema_name = match $name {
                "card-rich" => "card", "server-info-oidc" => "server-info", "feed-query-legacy" => "feed-query",
                "retention-command-absent" | "retention-command-reset" => "retention-command", n => n,
            };
            validator(&schemas[schema_name]).unwrap().validate(&raw).unwrap();
        )* };
    }
    cases! {
        LearnerPreferences => "learner-preferences", RetentionCommand => "retention-command", CardControlCommand => "card-control-command", LearnerCardControl => "learner-card-control", HiddenCardsPage => "hidden-cards-page",
        RetentionCommand => "retention-command-absent", RetentionCommand => "retention-command-reset",
        PasswordVerificationRequest => "password-verification-request", PasswordEmailRequest => "password-email-request",
        PasswordChallengeRequest => "password-challenge-request", PasswordResetRequest => "password-reset-request",
        PasswordChangeRequest => "password-change-request", PasswordRequestAccepted => "password-request-accepted",
        PasswordStatus => "password-status",
        DiagnosticReport => "diagnostic-report", DiagnosticReceipt => "diagnostic-receipt",
        ContentApkgImport=>"content-apkg-import", ContentProvenance=>"content-provenance", ContentMetadata=>"content-metadata", CardSave=>"card-save", PublicationCommand=>"publication-command", DeckEdit=>"deck-edit", ReportCreate=>"report-create", ContentReport=>"content-report", CardRevision=>"card-revision", StarterDeck=>"starter-deck", StarterInstall=>"starter-install", ContentImport=>"content-import",
        AccessSummary => "access-summary", AccessPage => "access-page",
        FavoriteCommand => "favorite-command",
        FavoriteState => "favorite-state",
        LibraryQuery => "library-query",
        LibraryEntry => "library-entry",
        LibraryPage => "library-page",
        ReviewHistoryEntry => "review-history-entry",
        ReviewHistoryPage => "review-history-page",
        FeedbackReceipt => "feedback-receipt",
        DeckImportRequest => "deck-import-request", ApkgImportRequest => "apkg-import-request",
        PrivacyPolicy => "privacy-policy", PrivacyRecord => "privacy-record", PrivacyState => "privacy-state", PrivacyUpdate => "privacy-update",

        ExplainOperation => "explain-operation", ExplainAccounting => "explain-accounting", ExplainReconcileRequest => "explain-reconcile-request",
        LoginRequest => "login-request", RegisterRequest => "register-request", ExplainRequest => "explain-request",
        SpeechDiagnostic => "speech-diagnostic", BgmClip => "bgm-clip", Card => "card-media",
        TtsSubmission => "tts-submission", TtsSubmissionItem => "tts-submission-item",
        TtsAttachmentReceipt => "tts-attachment-receipt", MembershipSummary => "membership-summary",
        WorkspaceConfirmation => "workspace-confirmation", CloseAccountRequest => "close-account-request",
        TransferOwnershipRequest => "transfer-ownership-request", PersonalWorkspaceExport => "personal-workspace-export",
        PersonalAccountExport => "personal-account-export", ExportAsset => "export-asset", WorkspaceExport => "workspace-export",
        SessionResponse => "session-response", SessionRefreshRequest => "session-refresh-request", SessionInfo => "session-info",
        AccountProfile => "account-profile", AccountSessionResponse => "account-session-response",
        WorkspaceSessionRequest => "workspace-session-request", AccountExport => "account-export", LinkedIdentity => "linked-identity",
        Card => "card", Card => "card-rich", CardDraft => "card-draft", RevisionPrecondition => "revision-precondition",
        PortableDeckPack => "portable-deck-pack", PortableMedia => "portable-media", PortableImportRequest => "portable-import-request",
        Deck => "deck", DeckPack => "deck-pack", CardExplanation => "card-explanation", BgmTrack => "bgm-track",
        FeedQuery => "feed-query", FeedQuery => "feed-query-legacy", FeedPage => "feed-page", PrefetchManifest => "prefetch-manifest",
        LearningStats => "learning-stats", FeedbackBatch => "feedback-batch", FeedbackAck => "feedback-ack",
        ServerInfo => "server-info", ServerInfo => "server-info-oidc", OidcStartRequest => "oidc-start-request",
        OidcStartResponse => "oidc-start-response", OidcCompleteRequest => "oidc-complete-request",
        OidcExchangeRequest => "oidc-exchange-request", AuthResponse => "auth-response", ApiError => "api-error",
    }
    assert_eq!(covered, fixtures.keys().copied().collect(), "fixture/codec coverage must be bidirectional");
}

#[test]
fn compatibility_recursive_validation_rejects_nested_damage_and_external_refs() {
    let schema = serde_json::to_value(schemars::schema_for!(FeedPage)).unwrap();
    let check = validator(&schema).unwrap();
    let page = serde_json::to_value(examples::sample_feed_page()).unwrap();
    assert!(check.is_valid(&page));
    let mut bad = page.clone();
    bad["items"][0]["card"].as_object_mut().unwrap().remove("id");
    assert!(!check.is_valid(&bad));
    let mut bad = page.clone();
    bad["items"][0]["slot"] = json!(-1);
    assert!(!check.is_valid(&bad));
    let mut bad = page.clone();
    bad["items"][0]["card"]["front"]["blocks"] = json!("not-a-list");
    assert!(!check.is_valid(&bad));
    let mut bad = page.clone();
    bad["items"][0]["card"]["front"]["blocks"] = json!([{"type":"unknown"}]);
    assert!(!check.is_valid(&bad));
    let mut bad = page.clone();
    bad["items"][0]["card"]["created_at"] = json!("not-a-date");
    assert!(!check.is_valid(&bad));
    let mut bad = page;
    bad["items"] = Value::Null;
    assert!(!check.is_valid(&bad));
    for uri in ["https://example.invalid/schema", concat!("file:", "///synthetic/schema.json")] {
        assert!(validator(&json!({"$ref":uri})).is_err());
    }
}

#[test]
fn compatibility_defaults_never_invent_authority_and_strict_requests_stay_strict() {
    let request: ExplainRequest = serde_json::from_value(json!({"future":true})).unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), json!({}));
    assert!(serde_json::from_value::<WorkspaceConfirmation>(json!({})).is_err());
    assert!(serde_json::from_value::<WorkspaceConfirmation>(json!({"confirmed_tenant_id":null})).is_err());
    assert!(serde_json::from_value::<WorkspaceConfirmation>(json!({"confirmed_tenant_id":"a","extra":true})).is_err());
    assert!(serde_json::from_value::<SessionRefreshRequest>(json!({"refresh_token":"r","extra":true})).is_err());
    assert!(serde_json::from_value::<CloseAccountRequest>(json!({"confirmed_user_id":"a"})).is_err());
    let mut info = serde_json::to_value(examples::sample_server_info()).unwrap();
    info.as_object_mut().unwrap().remove("opaque_sessions");
    assert!(!serde_json::from_value::<ServerInfo>(info.clone()).unwrap().opaque_sessions);
    info["opaque_sessions"] = json!(false);
    assert!(!serde_json::from_value::<ServerInfo>(info.clone()).unwrap().opaque_sessions);
    info["opaque_sessions"] = json!(true);
    assert!(serde_json::from_value::<ServerInfo>(info).unwrap().opaque_sessions);
}

#[test]
fn compatibility_frozen_schemas_validate_historical_inputs_and_current_defaults_are_explicit() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for minor in 1..=21 {
        let dir = root.join(format!("compatibility/history/2.{minor}.0/protocol"));
        let mut names =
            vec!["server-info", "feed-page", "feedback-batch", "api-error", "auth-response", "card", "deck"];
        if minor >= 11 {
            names.extend(["deck-import-request", "apkg-import-request"]);
        }
        if minor >= 13 {
            names.extend(["portable-deck-pack", "portable-media", "portable-import-request"]);
        }
        if minor >= 15 {
            names.extend([
                "password-verification-request",
                "password-email-request",
                "password-challenge-request",
                "password-reset-request",
                "password-change-request",
                "password-request-accepted",
                "password-status",
            ]);
        }
        if minor >= 16 {
            names.extend(["diagnostic-report", "diagnostic-receipt"]);
        }
        if minor >= 19 {
            names.extend(["access-summary", "access-page"]);
        }
        if minor >= 20 {
            names.extend([
                "favorite-command",
                "favorite-state",
                "library-query",
                "library-entry",
                "library-page",
                "review-history-entry",
                "review-history-page",
                "feedback-receipt",
            ]);
        }
        if minor >= 21 {
            names.extend(["card-media", "speech-diagnostic", "bgm-clip"]);
        }
        for name in names {
            let raw: Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join(format!("fixtures/{name}.json"))).unwrap())
                    .unwrap();
            let schema: Value = serde_json::from_str(
                &std::fs::read_to_string(dir.join(format!("schemas/{name}.schema.json"))).unwrap(),
            )
            .unwrap();
            validator(&schema).unwrap().validate(&raw).unwrap();
            if name == "feed-page" {
                let page: FeedPage = serde_json::from_value(raw.clone()).unwrap();
                assert_eq!(page.session_id, raw["session_id"]);
                if minor < 8 {
                    assert!(page.mode.is_none());
                    assert!(page.items.iter().all(|item| item.delivery_id.is_none()));
                }
            }
        }
    }
    let schema = serde_json::to_value(schemars::schema_for!(RegisterRequest)).unwrap();
    let check = validator(&schema).unwrap();
    let omitted = json!({"email":"e","password":"p","display_name":"n"});
    let mut nullable = omitted.clone();
    nullable["tenant_name"] = Value::Null;
    assert!(check.is_valid(&omitted) && check.is_valid(&nullable));
    assert_eq!(
        serde_json::from_value::<RegisterRequest>(omitted).unwrap(),
        serde_json::from_value::<RegisterRequest>(nullable).unwrap()
    );
}

// 与固定集成基线差分核对全部历史输入；较早主线已存在的字段缺省补全保持原样。
#[test]
fn compatibility_every_frozen_fixture_preserves_canonical_bytes() {
    let baseline: Value =
        serde_json::from_str(include_str!("../../../../compatibility/roundtrip-baseline-2.16.json")).unwrap();
    assert_eq!(baseline["protocol"], "2.16.0");
    assert_eq!(baseline["fixture_inputs_sha256"], "0624fbbd1494a3c3e14d4d17c16046ef174df7a48bf7c27281154a3c2af5ade6");
    let mut compared = BTreeSet::new();
    for minor in 1..=21 {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../../compatibility/history/2.{minor}.0/protocol/fixtures"));
        let fixtures: BTreeMap<String, Value> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
                let raw = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                (name, raw)
            })
            .collect();
        let mut covered = BTreeSet::new();
        macro_rules! cases {
        ($($ty:ty => $name:literal),* $(,)?) => { $(
            assert!(covered.insert($name.to_owned()), "duplicate frozen codec");
            if let Some(raw) = fixtures.get($name) {
            let decoded: $ty = serde_json::from_value(raw.clone()).unwrap();
            let roundtrip = serde_json::to_value(decoded).unwrap();
            let identity = format!("2.{minor}.0/{}", $name);
            if minor <= 16 {
                assert_eq!(&roundtrip, &baseline["roundtrips"][&identity], "differential roundtrip: {}", identity);
                compared.insert(identity.clone());
            }
            if minor >= 13 {
                assert_eq!(&roundtrip, raw, "canonical roundtrip: {}", identity);
            }
            } else { covered.remove($name); }
        )* };
    }
        cases! {
            FavoriteCommand => "favorite-command", FavoriteState => "favorite-state", LibraryQuery => "library-query", LibraryEntry => "library-entry", LibraryPage => "library-page", ReviewHistoryEntry => "review-history-entry", ReviewHistoryPage => "review-history-page", FeedbackReceipt => "feedback-receipt",
            ExplainOperation => "explain-operation", ExplainAccounting => "explain-accounting", ExplainReconcileRequest => "explain-reconcile-request",
            AccessSummary => "access-summary", AccessPage => "access-page",
            PasswordVerificationRequest => "password-verification-request", PasswordEmailRequest => "password-email-request", PasswordChallengeRequest => "password-challenge-request", PasswordResetRequest => "password-reset-request", PasswordChangeRequest => "password-change-request", PasswordRequestAccepted => "password-request-accepted", PasswordStatus => "password-status",
            DiagnosticReport => "diagnostic-report", DiagnosticReceipt => "diagnostic-receipt",
            ContentApkgImport=>"content-apkg-import", ContentProvenance=>"content-provenance", ContentMetadata=>"content-metadata", CardSave=>"card-save", PublicationCommand=>"publication-command", DeckEdit=>"deck-edit", ReportCreate=>"report-create", ContentReport=>"content-report", CardRevision=>"card-revision", StarterDeck=>"starter-deck", StarterInstall=>"starter-install", ContentImport=>"content-import",
            DeckImportRequest => "deck-import-request", ApkgImportRequest => "apkg-import-request",
            PrivacyPolicy => "privacy-policy", PrivacyRecord => "privacy-record", PrivacyState => "privacy-state", PrivacyUpdate => "privacy-update",
            LoginRequest => "login-request", RegisterRequest => "register-request", ExplainRequest => "explain-request",
            SpeechDiagnostic => "speech-diagnostic", BgmClip => "bgm-clip", Card => "card-media",
            TtsSubmission => "tts-submission", TtsSubmissionItem => "tts-submission-item",
            TtsAttachmentReceipt => "tts-attachment-receipt", MembershipSummary => "membership-summary",
            WorkspaceConfirmation => "workspace-confirmation", CloseAccountRequest => "close-account-request",
            TransferOwnershipRequest => "transfer-ownership-request", PersonalWorkspaceExport => "personal-workspace-export",
            PersonalAccountExport => "personal-account-export", ExportAsset => "export-asset", WorkspaceExport => "workspace-export",
            SessionResponse => "session-response", SessionRefreshRequest => "session-refresh-request", SessionInfo => "session-info",
            AccountProfile => "account-profile", AccountSessionResponse => "account-session-response",
            WorkspaceSessionRequest => "workspace-session-request", AccountExport => "account-export", LinkedIdentity => "linked-identity",
            Card => "card", Card => "card-rich", CardDraft => "card-draft", RevisionPrecondition => "revision-precondition",
            PortableDeckPack => "portable-deck-pack", PortableMedia => "portable-media", PortableImportRequest => "portable-import-request",
            Deck => "deck", DeckPack => "deck-pack", CardExplanation => "card-explanation", BgmTrack => "bgm-track",
            FeedQuery => "feed-query", FeedQuery => "feed-query-legacy", FeedPage => "feed-page", PrefetchManifest => "prefetch-manifest",
            LearningStats => "learning-stats", FeedbackBatch => "feedback-batch", FeedbackAck => "feedback-ack",
            ServerInfo => "server-info", ServerInfo => "server-info-oidc", OidcStartRequest => "oidc-start-request",
            OidcStartResponse => "oidc-start-response", OidcCompleteRequest => "oidc-complete-request",
            OidcExchangeRequest => "oidc-exchange-request", AuthResponse => "auth-response", ApiError => "api-error",
        }
        assert_eq!(covered, fixtures.keys().cloned().collect(), "every frozen fixture needs a codec");
    }
    assert_eq!(compared, baseline["roundtrips"].as_object().unwrap().keys().cloned().collect());
}

#[test]
fn access_optional_fields_keep_frozen_identity() {
    for raw in [
        json!({"id":"id","kind":"future","status":"unknown"}),
        serde_json::to_value(examples::sample_access_summary()).unwrap(),
    ] {
        roundtrip::<AccessSummary>(raw);
    }
    roundtrip::<AccessPage>(json!({"items":[]}));
    let value: AccessSummary =
        serde_json::from_value(json!({"id":"id","kind":"future","status":"unknown","future":true})).unwrap();
    assert_eq!(value.tenant_id, None);
    assert_eq!(value.current, None);
    assert_eq!(value.scopes_limited, None);
    for limited in [false, true] {
        roundtrip::<AccessSummary>(
            json!({"id":"mixed","kind":"api-tokens","status":"active","scopes":["content:read"],"scopes_limited":limited}),
        );
    }
}

#[test]
fn library_additions_preserve_frozen_feedback_ack_identity() {
    for minor in 1..=19 {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../../compatibility/history/2.{minor}.0/protocol/fixtures/feedback-ack.json"));
        if path.exists() {
            roundtrip::<FeedbackAck>(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap());
        }
    }
    let raw = serde_json::json!({"accepted":1,"duplicates":0,"rejected":[]});
    roundtrip::<FeedbackAck>(raw);
}

#[test]
fn media_extensions_preserve_omission_and_unknown_quality() {
    let old = serde_json::to_value(examples::sample_card()).unwrap();
    roundtrip::<Card>(old.clone());
    for quality in ["native", "estimated", "unknown"] {
        let mut value = old.clone();
        value["tts"]["alignment_quality"] = json!(quality);
        roundtrip::<Card>(value);
    }
    let mut future = old.clone();
    future["tts"]["alignment_quality"] = json!("future-quality");
    let card: Card = serde_json::from_value(future).unwrap();
    assert_eq!(card.tts.unwrap().alignment_quality, Some(AlignmentQuality::Unknown));
    for field in ["alignment_quality", "audio_kind", "provenance"] {
        let mut value = old.clone();
        value["tts"][field] = Value::Null;
        let decoded: Card = serde_json::from_value(value).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), old);
    }
    let card = examples::sample_media_card();
    roundtrip::<Card>(serde_json::to_value(&card).unwrap());
    assert_eq!(card.tts.unwrap().alignment_quality, Some(AlignmentQuality::Estimated));
}
