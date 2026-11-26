//! 确定性示例数据：用于生成 `protocol/fixtures/*.json`，供服务端与 App 双端契约测试共同使用。

use chrono::{DateTime, TimeZone, Utc};

use crate::*;

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + secs, 0).single().expect("valid timestamp")
}

/// 示例 TTS 音频资产。
pub fn sample_tts_asset() -> AssetRef {
    AssetRef {
        key: "tenants/local/tts/9f2c1e.wav".into(),
        url: "/assets/tenants/local/tts/9f2c1e.wav".into(),
        mime: "audio/wav".into(),
        bytes: 52_964,
        sha256: "9f2c1e8a4b7d6f00112233445566778899aabbccddeeff001122334455667780".into(),
    }
}

/// 示例 BGM 曲目。
pub fn sample_bgm_track() -> BgmTrack {
    BgmTrack {
        provenance: None,
        pcm: None,
        revision: 1,
        id: "bgm_focus_pad".into(),
        title: "Focus Pad".into(),
        artist: Some("Memoswish Synth".into()),
        asset: AssetRef {
            key: "shared/bgm/focus_pad.wav".into(),
            url: "/assets/shared/bgm/focus_pad.wav".into(),
            mime: "audio/wav".into(),
            bytes: 1_323_044,
            sha256: "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9".into(),
        },
        duration_ms: 30_000,
        bpm: 90,
        moods: vec!["focus".into(), "calm".into()],
        energy: 0.35,
        loop_start_ms: 0,
        loop_end_ms: 30_000,
        license: "generated".into(),
    }
}

/// 示例卡片：语言学习卡，带逐词时间戳、BGM 与闪避参数。
pub fn sample_card() -> Card {
    Card {
        content: None,
        id: "0192f3a0-0000-7000-8000-000000000001".into(),
        deck_id: "0192f3a0-0000-7000-8000-0000000000d1".into(),
        template: "term".into(),
        language: "en-US".into(),
        front: CardFace {
            title: "serendipity".into(),
            subtitle: Some("/ˌserənˈdɪpəti/".into()),
            blocks: vec![ContentBlock::text("Finding something good without looking for it.")],
        },
        back: CardFace {
            title: "意外发现美好事物的运气".into(),
            subtitle: None,
            blocks: vec![
                ContentBlock::Quote { text: "It was pure serendipity that we met.".into(), source: None },
                ContentBlock::text("我们相遇纯属机缘巧合。"),
            ],
        },
        tags: vec!["english".into(), "b2".into()],
        attributes: serde_json::Map::new(),
        tts: Some(TtsTrack {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            audio: sample_tts_asset(),
            text: "serendipity, finding something good".into(),
            language: "en-US".into(),
            voice: "default".into(),
            engine: "placeholder".into(),
            duration_ms: 2_400,
            words: vec![
                WordTimestamp { text: "serendipity,".into(), start_ms: 0, end_ms: 900, char_start: 0, char_end: 12 },
                WordTimestamp { text: "finding".into(), start_ms: 1_000, end_ms: 1_450, char_start: 13, char_end: 20 },
                WordTimestamp {
                    text: "something".into(),
                    start_ms: 1_500,
                    end_ms: 1_950,
                    char_start: 21,
                    char_end: 30,
                },
                WordTimestamp { text: "good".into(), start_ms: 2_000, end_ms: 2_400, char_start: 31, char_end: 35 },
            ],
        }),
        bgm: Some(BgmBinding {
            track: sample_bgm_track(),
            policy: BgmPolicy::Continue,
            theme_key: "vocab-calm".into(),
            base_volume: 0.6,
        }),
        ducking: DuckingParams::default(),
        visual: CardVisual::default(),
        revision: 3,
        created_at: ts(0),
        updated_at: ts(3_600),
    }
}

/// 示例卡片：覆盖全部内容块类型与领域元数据（物理学），供客户端渲染与契约测试。
pub fn sample_rich_card() -> Card {
    let mut attributes = serde_json::Map::new();
    attributes.insert("field".into(), serde_json::json!("physics"));
    attributes.insert("year".into(), serde_json::json!(1905));
    attributes.insert("difficulty".into(), serde_json::json!(2));
    Card {
        content: None,
        id: "0192f3a0-0000-7000-8000-000000000002".into(),
        deck_id: "0192f3a0-0000-7000-8000-0000000000d2".into(),
        template: "formula".into(),
        language: "zh-CN".into(),
        front: CardFace {
            title: "质能方程说了什么？".into(),
            subtitle: Some("Albert Einstein · 1905".into()),
            blocks: vec![ContentBlock::Math { latex: "E = mc^2".into(), display: true }],
        },
        back: CardFace {
            title: "质量与能量可以相互转化".into(),
            subtitle: None,
            blocks: vec![
                ContentBlock::text("**E** 是能量，**m** 是质量，**c** 是光速。"),
                ContentBlock::List {
                    items: vec!["核裂变".into(), "核聚变".into(), "正负电子湮灭".into()],
                    ordered: false,
                },
                ContentBlock::Table {
                    header: vec!["符号".into(), "单位".into()],
                    rows: vec![
                        vec!["E".into(), "J".into()],
                        vec!["m".into(), "kg".into()],
                        vec!["c".into(), "m/s".into()],
                    ],
                },
                ContentBlock::Code {
                    language: "python".into(),
                    source: "c = 299_792_458\nE = 0.001 * c ** 2  # 1 克质量\nprint(f\"{E:.3e} J\")".into(),
                    highlight_lines: vec![2],
                },
                ContentBlock::Image { asset: sample_image_asset(), alt: "Einstein at the blackboard".into() },
                ContentBlock::Quote {
                    text: "Imagination is more important than knowledge.".into(),
                    source: Some("Albert Einstein".into()),
                },
                ContentBlock::Link {
                    url: "https://en.wikipedia.org/wiki/Mass%E2%80%93energy_equivalence".into(),
                    title: Some("Wikipedia".into()),
                },
            ],
        },
        tags: vec!["physics".into()],
        attributes,
        tts: None,
        bgm: None,
        ducking: DuckingParams::default(),
        visual: CardVisual { background: "#0B1021".into(), accent: "#25F4EE".into(), image: None },
        revision: 1,
        created_at: ts(10),
        updated_at: ts(10),
    }
}

/// 示例图片资产。
pub fn sample_image_asset() -> AssetRef {
    AssetRef {
        key: "tenants/local/images/5e1a.png".into(),
        url: "/assets/tenants/local/images/5e1a.png".into(),
        mime: "image/png".into(),
        bytes: 20_480,
        sha256: "5e1a7c0d2b3f4e5a69788796a5b4c3d2e1f00112233445566778899aabbccdd0".into(),
    }
}

/// 示例卡组。
pub fn sample_deck() -> Deck {
    Deck {
        revision: Some(1),
        id: "0192f3a0-0000-7000-8000-0000000000d1".into(),
        title: "English Vocabulary Starter".into(),
        description: "High-frequency B2 words.".into(),
        language: "en-US".into(),
        tags: vec!["english".into()],
        card_count: 1,
        created_at: ts(0),
    }
}

/// 示例信息流分页。
pub fn sample_feed_page() -> FeedPage {
    let card = sample_card();
    let code = sample_rich_card();
    FeedPage {
        mode: Some("learning".into()),
        policy_version: Some("delivery-v1-example".into()),
        session_id: "sess_0192f3a0".into(),
        items: vec![
            FeedItem {
                delivery_id: Some("dlv_example_0".into()),
                slot: 0,
                reason: FeedReason::New,
                card: card.clone(),
                retrievability: None,
            },
            FeedItem {
                delivery_id: Some("dlv_example_1".into()),
                slot: 1,
                reason: FeedReason::Due,
                card: code.clone(),
                retrievability: Some(0.82),
            },
        ],
        next_cursor: "s:2".into(),
        prefetch: PrefetchManifest {
            window_before: 3,
            window_after: 5,
            entries: vec![
                PrefetchEntry {
                    slot: 0,
                    card_id: card.id.clone(),
                    priority: 0,
                    assets: vec![sample_tts_asset(), sample_bgm_track().asset],
                },
                PrefetchEntry { slot: 1, card_id: code.id.clone(), priority: 1, assets: vec![sample_image_asset()] },
            ],
            expires_at: None,
        },
        generated_at: ts(7_200),
    }
}

/// 示例埋点批次。
pub fn sample_feedback_batch() -> FeedbackBatch {
    FeedbackBatch {
        session_id: "sess_0192f3a0".into(),
        client_id: "client_7d1e".into(),
        sent_at: ts(7_300),
        events: vec![
            ImplicitFeedback {
                delivery_id: None,
                event_id: "6f1c1d2e-0000-4000-8000-000000000001".into(),
                card_id: "0192f3a0-0000-7000-8000-000000000001".into(),
                slot: 0,
                shown_at: ts(7_210),
                dwell_time_ms: 5_400,
                loop_count: 2,
                swipe_velocity: 0.8,
                swipe_direction: SwipeDirection::Next,
                flipped: true,
                double_tapped: true,
                long_pressed: false,
                muted: false,
            },
            ImplicitFeedback {
                delivery_id: None,
                event_id: "6f1c1d2e-0000-4000-8000-000000000002".into(),
                card_id: "0192f3a0-0000-7000-8000-000000000002".into(),
                slot: 1,
                shown_at: ts(7_216),
                dwell_time_ms: 900,
                loop_count: 0,
                swipe_velocity: 3.2,
                swipe_direction: SwipeDirection::Next,
                flipped: false,
                double_tapped: false,
                long_pressed: false,
                muted: false,
            },
        ],
    }
}

/// 示例埋点回执。
pub fn sample_feedback_ack() -> FeedbackAck {
    FeedbackAck { receipts: None, accepted: 2, duplicates: 0, rejected: vec![] }
}

/// 示例服务端信息。
pub fn sample_server_info() -> ServerInfo {
    ServerInfo {
        name: "memoswishd".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: PROTOCOL_VERSION.into(),
        mode: DeploymentMode::SingleUser,
        features: vec!["self-hosted".into()],
        registration_open: false,
        opaque_sessions: true,
        content_lifecycle: Some(true),
        oidc_providers: vec![],
        tts_engines: vec!["placeholder".into()],
    }
}

/// 商业服务端的第三方登录能力示例。
pub fn sample_server_info_oidc() -> ServerInfo {
    ServerInfo {
        mode: DeploymentMode::MultiTenant,
        features: vec!["commercial-saas".into()],
        registration_open: true,
        oidc_providers: vec![
            OidcProviderInfo { id: "google".into(), name: "Google".into(), native: true },
            OidcProviderInfo { id: "apple".into(), name: "Apple".into(), native: true },
        ],
        ..sample_server_info()
    }
}

/// 示例认证响应。
pub fn sample_auth_response() -> AuthResponse {
    AuthResponse {
        access_token: "eyJhbGciOiJIUzI1NiJ9.e30.sig".into(),
        token_type: "Bearer".into(),
        expires_in: 86_400,
        user: UserProfile {
            user_id: "usr_local".into(),
            tenant_id: "local".into(),
            display_name: "Local Owner".into(),
            role: "owner".into(),
        },
    }
}

/// 示例错误响应。
pub fn sample_api_error() -> ApiError {
    ApiError { code: "not_found".into(), message: "card not found".into() }
}

/// 示例学习统计。
pub fn sample_learning_stats() -> LearningStats {
    LearningStats {
        total_cards: 18,
        seen_cards: 12,
        due_cards: 3,
        starred_cards: 4,
        average_retrievability: 0.88,
        total_exposures: 42,
    }
}

/// 示例卡片深度解析。
pub fn sample_card_explanation() -> CardExplanation {
    CardExplanation {
        operation: None,
        card_id: "0192f3a0-0000-7000-8000-000000000001".into(),
        summary: "serendipity 指在没有刻意寻找时，意外遇到美好事物或灵感的好运气。".into(),
        key_points: vec![
            "词源来自波斯童话《锡兰三王子》（The Three Princes of Serendip）。".into(),
            "常搭配 pure / happy / by serendipity 使用。".into(),
        ],
        analogy: "就像去书店找一本工具书，却在旁边书架偶遇了改变人生的小说。".into(),
        follow_up_questions: vec![
            "serendipity 和 luck 有什么细微区别？".into(),
            "形容词形式 serendipitous 怎么造句？".into(),
        ],
        provider: "builtin-heuristic".into(),
        generated_at: ts(7_400),
    }
}

/// 示例卡组内容包。
pub fn sample_deck_pack() -> DeckPack {
    DeckPack { version: "1.0".into(), deck: sample_deck(), cards: vec![sample_card()], exported_at: ts(7_500) }
}

/// 所有 fixture，键为文件名（不含扩展名）。
pub fn sample_privacy_policy() -> PrivacyPolicy {
    PrivacyPolicy {
        hosted: true,
        notice_version: "notice-v1".into(),
        terms_version: "terms-v1".into(),
        privacy_url: "https://operator.example/privacy".into(),
        terms_url: "https://operator.example/terms".into(),
        allowed_regions: vec!["example-region".into()],
        purpose_versions: std::collections::BTreeMap::from([("external_ai".into(), "provider-policy-v1".into())]),
    }
}
pub fn sample_privacy_record() -> PrivacyRecord {
    PrivacyRecord {
        kind: "notice".into(),
        version: "notice-v1".into(),
        decision: true,
        value: String::new(),
        recorded_at: 1794096000,
        evidence: "self_assertion".into(),
    }
}
pub fn sample_privacy_update() -> PrivacyUpdate {
    PrivacyUpdate {
        expected_revision: 0,
        kind: "notice".into(),
        version: "notice-v1".into(),
        decision: true,
        value: String::new(),
    }
}
pub fn sample_diagnostic_report() -> DiagnosticReport {
    DiagnosticReport {
        report_id: "0123456789abcdef0123456789abcdef".into(),
        privacy_revision: 4,
        captured_at_ms: 1794096000000,
        purpose_version: "diagnostics-v1".into(),
        build: env!("CARGO_PKG_VERSION").into(),
        platform: "linux".into(),
        category: "flutter".into(),
        code: "framework_error".into(),
        frames: vec!["presentation".into()],
    }
}
pub fn all_fixtures() -> Vec<(&'static str, serde_json::Value)> {
    fn v<T: serde::Serialize>(t: T) -> serde_json::Value {
        serde_json::to_value(t).expect("fixture serializes")
    }
    let workspace = PersonalWorkspaceExport {
        tenant_id: "workspace".into(),
        role: "owner".into(),
        exclusive: true,
        data: ExportRows::from([(
            "feed_deliveries".into(),
            vec![serde_json::json!({
                "session_id": "session", "slot": 0, "delivery_id": "delivery",
                "body": {
                    "attribution": {
                        "delivery_id": "delivery", "policy_version": "policy-v1",
                        "revision_at_issuance": 1, "issued_at": "2026-11-07T00:00:00Z"
                    },
                    "card_id": "card",
                    "policy": {"version": "policy-v1", "configuration": "{}"}
                }
            })],
        )]),
    };
    let asset = ExportAsset {
        key: "tenants/workspace/example".into(),
        mime: "text/plain".into(),
        encoding: "hex".into(),
        data: "6869".into(),
    };
    vec![
        (
            "learner-preferences",
            v(LearnerPreferences { revision: 1, desired_retention: Some(0.85), effective_retention: 0.85 }),
        ),
        ("retention-command", v(RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.85)) })),
        ("retention-command-absent", v(RetentionCommand { expected_revision: 0, desired_retention: None })),
        ("retention-command-reset", v(RetentionCommand { expected_revision: 0, desired_retention: Some(None) })),
        ("card-control-command", v(CardControlCommand { expected_revision: 0, action: CardControlAction::Bury })),
        (
            "learner-card-control",
            v(LearnerCardControl {
                card_id: sample_card().id,
                revision: 1,
                suspended: false,
                buried_until: Some(ts(86400)),
            }),
        ),
        (
            "hidden-cards-page",
            v(HiddenCardsPage {
                items: vec![LearnerCardControl {
                    card_id: sample_card().id,
                    revision: 1,
                    suspended: true,
                    buried_until: None,
                }],
                next_after: None,
            }),
        ),
        (
            "password-verification-request",
            v(PasswordVerificationRequest { email: "learner@example.com".into(), password: "example-password".into() }),
        ),
        ("password-email-request", v(PasswordEmailRequest { email: "learner@example.com".into() })),
        (
            "password-challenge-request",
            v(PasswordChallengeRequest { email: "learner@example.com".into(), token: "example-only".into() }),
        ),
        (
            "password-reset-request",
            v(PasswordResetRequest {
                email: "learner@example.com".into(),
                token: "example-only".into(),
                new_password: "example-password-new".into(),
            }),
        ),
        (
            "password-change-request",
            v(PasswordChangeRequest {
                current_password: "example-password".into(),
                new_password: "example-password-new".into(),
            }),
        ),
        ("password-request-accepted", v(PasswordRequestAccepted { accepted: true })),
        ("access-summary", v(sample_access_summary())),
        ("access-page", v(AccessPage { items: vec![sample_access_summary()], next_cursor: Some("session-a".into()) })),
        ("password-status", v(PasswordStatus { password_enabled: true, email_verified: false, mail_available: true })),
        ("diagnostic-report", v(sample_diagnostic_report())),
        (
            "diagnostic-receipt",
            v(DiagnosticReceipt { report_id: sample_diagnostic_report().report_id, duplicate: false }),
        ),
        (
            "content-provenance",
            v(ContentProvenance {
                method: "manual".into(),
                sources: vec!["https://example.org/reference".into()],
                attribution: "Author".into(),
                rights: "Apache-2.0".into(),
                source_id: Some("source-card".into()),
                source_id_is_digest: false,
                source_revision: Some(2),
                provider_claim: Some("caller claim, unverified".into()),
                source_generation_claim: Some("source-server-claim".into()),
                source_publication_claim: Some("draft".into()),
            }),
        ),
        (
            "content-metadata",
            v(ContentMetadata {
                observed_generation: Some("builtin-heuristic".into()),
                publication: "draft".into(),
                provenance: Default::default(),
            }),
        ),
        (
            "card-save",
            v(CardSave {
                card: serde_json::from_value(
                    serde_json::json!({"deck_id":"deck-example","front":{"title":"Question"}}),
                )
                .unwrap(),
                publish: false,
                provenance: None,
                report_id: None,
            }),
        ),
        ("publication-command", v(PublicationCommand { expected_revision: 3, publish: true })),
        (
            "deck-edit",
            v(DeckEdit {
                expected_revision: 1,
                title: "Updated".into(),
                description: "Private".into(),
                language: "zh-CN".into(),
            }),
        ),
        ("report-create", v(ReportCreate { observed_revision: 3, text: "Check this answer".into(), sources: vec![] })),
        (
            "content-report",
            v(ContentReport {
                id: "report-example".into(),
                card_id: "card-example".into(),
                user_id: "user-example".into(),
                observed_revision: 3,
                evidence_available: true,
                text: "Check this answer".into(),
                sources: vec![],
                created_at: sample_card().created_at,
                corrected_revision: Some(4),
            }),
        ),
        ("card-revision", v(CardRevision { revision: sample_card().revision, card: sample_card() })),
        (
            "starter-deck",
            v(StarterDeck {
                id: "learning-basics-v1".into(),
                title: "从三张卡开始".into(),
                description: "学习方法".into(),
                attribution: "Memoswish contributors".into(),
                rights: "Apache-2.0".into(),
            }),
        ),
        ("starter-install", v(StarterInstall { idempotency_key: "install-example".into() })),
        (
            "content-import",
            v(ContentImport {
                pack: sample_portable_deck_pack(),
                idempotency_key: "import-example".into(),
                publish: false,
            }),
        ),
        (
            "content-apkg-import",
            v(ContentApkgImport {
                apkg: crate::ApkgImportRequest {
                    apkg_base64: "AA==".into(),
                    title: None,
                    language: None,
                    request_id: Some("apkg-example".into()),
                },
                publish: false,
            }),
        ),
        ("privacy-policy", v(sample_privacy_policy())),
        ("privacy-record", v(sample_privacy_record())),
        ("privacy-update", v(sample_privacy_update())),
        (
            "privacy-state",
            v(PrivacyState { revision: 1, account_records: vec![sample_privacy_record()], purpose_records: vec![] }),
        ),
        (
            "explain-reconcile-request",
            v(ExplainReconcileRequest {
                input_tokens: Some(10),
                output_tokens: Some(2),
                not_charged_reference_sha256: None,
            }),
        ),
        (
            "explain-accounting",
            v(ExplainAccounting {
                requests: 1,
                attempts: 1,
                period: "2026-11".into(),
                currency: "USD".into(),
                held_microcurrency: 0,
                committed_microcurrency: 2,
                input_tokens: Some(10),
                output_tokens: Some(2),
            }),
        ),
        ("login-request", v(LoginRequest { email: "learner@example.com".into(), password: "fixture-password".into() })),
        (
            "register-request",
            v(RegisterRequest {
                email: "learner@example.com".into(),
                password: "fixture-password".into(),
                display_name: "Learner".into(),
                tenant_name: Some("Workspace".into()),
            }),
        ),
        (
            "explain-operation",
            v(ExplainOperation {
                accounting: None,
                request_id: "explain-1".into(),
                disposition: ExplainDisposition::Unresolved,
            }),
        ),
        (
            "explain-request",
            v(ExplainRequest {
                request_id: Some("explain-1".into()),
                question: Some("Why?".into()),
                locale: Some("zh-CN".into()),
            }),
        ),
        ("prefetch-manifest", v(sample_feed_page().prefetch)),
        (
            "speech-diagnostic",
            v(SpeechDiagnostic {
                engine: "espeak-ng".into(),
                configured: true,
                state: SpeechDiagnosticState::Available,
                voices: vec!["cmn".into(), "en-us".into()],
            }),
        ),
        (
            "bgm-clip",
            v(BgmClip {
                request_id: "clip-request".into(),
                track_id: "bgm_focus".into(),
                start_frame: 1,
                end_frame: 100,
                title: None,
            }),
        ),
        ("card-media", v(sample_media_card())),
        ("tts-submission", v(sample_tts_submission())),
        ("tts-submission-item", v(sample_tts_submission().items.remove(0))),
        ("tts-attachment-receipt", v(sample_tts_submission().items.remove(0).receipt.unwrap())),
        (
            "membership-summary",
            v(MembershipSummary { tenant_id: "workspace".into(), name: "Workspace".into(), role: "owner".into() }),
        ),
        ("workspace-confirmation", v(WorkspaceConfirmation { confirmed_tenant_id: "workspace".into() })),
        (
            "close-account-request",
            v(CloseAccountRequest {
                confirmed_user_id: sample_account_profile().user_id,
                confirmed_exclusive_workspaces: vec!["workspace".into()],
            }),
        ),
        ("transfer-ownership-request", v(TransferOwnershipRequest { successor_user_id: "successor".into() })),
        ("personal-workspace-export", v(workspace.clone())),
        (
            "personal-account-export",
            v(PersonalAccountExport {
                privacy_records: vec![serde_json::json!({"account_records":[sample_privacy_record()]})],
                account: sample_account_profile(),
                identities: vec![],
                workspaces: vec![workspace],
                session_metadata: vec![],
                exported_at: "2026-11-07T00:00:00+00:00".into(),
            }),
        ),
        ("export-asset", v(asset.clone())),
        (
            "workspace-export",
            v(WorkspaceExport {
                tenant_id: "workspace".into(),
                data: ExportRows::from([(
                    "tts_submission_items".into(),
                    vec![serde_json::json!({
                        "item_id": sample_tts_submission().items[0].item_id,
                        "receipt": sample_tts_submission().items[0].receipt
                    })],
                )]),
                assets: vec![asset],
                exported_at: "2026-11-07T00:00:00+00:00".into(),
            }),
        ),
        (
            "session-response",
            v(SessionResponse {
                access_token: "lts_at_synthetic".into(),
                refresh_token: "lts_rt_synthetic".into(),
                token_type: "Bearer".into(),
                expires_in: 900,
                session_id: "session".into(),
                account: sample_account_profile(),
                workspace: Some(sample_auth_response().user),
            }),
        ),
        ("session-refresh-request", v(SessionRefreshRequest { refresh_token: "lts_rt_synthetic".into() })),
        (
            "session-info",
            v(SessionInfo {
                session_id: "session".into(),
                provenance: "password".into(),
                auth_time: 100,
                expires_at: 1000,
                revoked: false,
                current: true,
            }),
        ),
        ("account-profile", v(sample_account_profile())),
        (
            "account-session-response",
            v(AccountSessionResponse {
                access_token: "account-jwt".into(),
                token_type: "Bearer".into(),
                expires_in: 3600,
                account: sample_account_profile(),
            }),
        ),
        ("workspace-session-request", v(WorkspaceSessionRequest { tenant_id: "workspace".into() })),
        ("account-export", v(AccountExport { account: sample_account_profile(), identities: vec![] })),
        (
            "linked-identity",
            v(LinkedIdentity {
                provider: "google".into(),
                issuer: "https://accounts.google.com".into(),
                subject: "provider-subject".into(),
                email: None,
            }),
        ),
        ("card", v(sample_card())),
        (
            "card-draft",
            v(CardDraft {
                id: Some(sample_card().id),
                expected_revision: Some(3),
                deck_id: sample_deck().id,
                template: Some("term".into()),
                language: Some("en-US".into()),
                front: sample_card().front,
                back: sample_card().back,
                tags: vec!["english".into()],
                attributes: Default::default(),
                ducking: Some(DuckingParams::default()),
                visual: Some(CardVisual::default()),
            }),
        ),
        ("revision-precondition", v(RevisionPrecondition { expected_revision: Some(3) })),
        ("card-rich", v(sample_rich_card())),
        ("deck", v(sample_deck())),
        ("deck-pack", v(sample_deck_pack())),
        ("portable-deck-pack", v(sample_portable_deck_pack())),
        ("portable-media", v(sample_portable_deck_pack().media.remove(0))),
        (
            "portable-import-request",
            v(PortableImportRequest { pack: sample_portable_deck_pack(), request_id: Some("portable-retry".into()) }),
        ),
        (
            "deck-import-request",
            v(DeckImportRequest {
                pack: sample_deck_pack(),
                auto_tts: Some(false),
                request_id: Some("import-example".into()),
            }),
        ),
        (
            "apkg-import-request",
            v(ApkgImportRequest {
                apkg_base64: "UEs=".into(),
                title: Some("导入示例".into()),
                language: Some("zh-CN".into()),
                request_id: Some("apkg-example".into()),
            }),
        ),
        ("card-explanation", v(sample_card_explanation())),
        ("bgm-track", v(sample_bgm_track())),
        (
            "feed-query",
            v(FeedQuery {
                mode: None,
                request_id: Some("first-request".into()),
                limit: Some(10),
                deck_id: Some(sample_deck().id),
                ..Default::default()
            }),
        ),
        ("feed-query-legacy", v(FeedQuery::default())),
        ("feed-page", v(sample_feed_page())),
        ("learning-stats", v(sample_learning_stats())),
        ("feedback-batch", v(sample_feedback_batch())),
        ("feedback-ack", v(sample_feedback_ack())),
        (
            "favorite-command",
            v(FavoriteCommand { operation_id: "favorite-op".into(), desired_state: false, expected_revision: 0 }),
        ),
        ("favorite-state", v(FavoriteState { card_id: "card".into(), starred: false, revision: 1 })),
        ("library-query", v(LibraryQuery { query: Some("%literal_".into()), limit: Some(50), ..Default::default() })),
        (
            "library-entry",
            v(LibraryEntry {
                control: None,
                card: sample_card(),
                favorite: FavoriteState { card_id: sample_card().id, starred: false, revision: 0 },
            }),
        ),
        (
            "library-page",
            v(LibraryPage {
                items: vec![LibraryEntry {
                    control: None,
                    card: sample_card(),
                    favorite: FavoriteState { card_id: sample_card().id, starred: false, revision: 0 },
                }],
                next_cursor: None,
            }),
        ),
        (
            "review-history-entry",
            v(ReviewHistoryEntry {
                control: None,
                event_id: "event".into(),
                card_id: "card".into(),
                received_at: sample_feedback_batch().sent_at,
                disposition: "legacy_unknown".into(),
                rating: None,
                archived: true,
            }),
        ),
        (
            "review-history-page",
            v(ReviewHistoryPage {
                items: vec![ReviewHistoryEntry {
                    control: None,
                    event_id: "event".into(),
                    card_id: "card".into(),
                    received_at: sample_feedback_batch().sent_at,
                    disposition: "not_rated".into(),
                    rating: None,
                    archived: false,
                }],
                next_cursor: None,
            }),
        ),
        (
            "feedback-receipt",
            v(FeedbackReceipt {
                event_id: "event".into(),
                outcome: "delivered".into(),
                disposition: Some("scheduled".into()),
            }),
        ),
        ("server-info", v(sample_server_info())),
        ("server-info-oidc", v(sample_server_info_oidc())),
        (
            "oidc-start-request",
            v(OidcStartRequest {
                return_uri: "com.memoswish.app:/auth/callback".into(),
                app_state: "app-state".into(),
                code_challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                native_client_id: None,
            }),
        ),
        (
            "oidc-start-response",
            v(OidcStartResponse {
                attempt_id: "attempt".into(),
                expires_in: 300,
                launch_url: Some(
                    "https://learn.example/v1/auth/oidc/google/start?attempt=attempt&launch=handle".into(),
                ),
                nonce: None,
            }),
        ),
        (
            "oidc-complete-request",
            v(OidcCompleteRequest {
                code: "completion-code".into(),
                code_verifier: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            }),
        ),
        (
            "oidc-exchange-request",
            v(OidcExchangeRequest {
                attempt_id: "attempt".into(),
                id_token: "provider-id-token".into(),
                authorization_code: None,
                apple_user: None,
                nonce: "nonce".into(),
                code_verifier: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            }),
        ),
        ("auth-response", v(sample_auth_response())),
        ("api-error", v(sample_api_error())),
    ]
}

/// 零成员账户没有工作区字段。
pub fn sample_account_profile() -> AccountProfile {
    AccountProfile { user_id: "account".into(), email: "learner@example.com".into(), display_name: "Learner".into() }
}

/// 不包含历史卡片或可过期 URL 的提交示例。
pub fn sample_tts_submission() -> crate::TtsSubmission {
    let receipt = crate::TtsAttachmentReceipt {
        item_id: "item-1".into(),
        card_id: "card-1".into(),
        expected_revision: 1,
        disposition: crate::TtsDisposition::Attached,
        resulting_revision: Some(2),
        asset_id: Some("asset-1".into()),
    };
    crate::TtsSubmission {
        request_id: "request-1".into(),
        complete: true,
        items: vec![crate::TtsSubmissionItem {
            item_id: "item-1".into(),
            card_id: "card-1".into(),
            expected_revision: 1,
            receipt: Some(receipt),
        }],
    }
}

/// 多槽位媒体示例保留完整的富卡片元数据，嵌入有效 PNG 和 PCM WAV。
pub fn sample_portable_deck_pack() -> PortableDeckPack {
    let media=vec![PortableMedia{id:"m0".into(),mime:"image/png".into(),bytes:68,sha256:"6b1048f8a6d40bac0b2954c18fefa40c4ea7a96120fc2e54b7317c0e43c2bbec".into(),data_base64:"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=".into()},PortableMedia{id:"m1".into(),mime:"audio/wav".into(),bytes:204,sha256:"60c0b6c740c791f5d9c1b7d688aa4e6719b93c8f4e7c4b7919ab86ad78b74068".into(),data_base64:"UklGRsQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()}];
    let asset = |m: &PortableMedia| AssetRef {
        key: m.id.clone(),
        url: String::new(),
        mime: m.mime.clone(),
        bytes: m.bytes,
        sha256: m.sha256.clone(),
    };
    let mut card = sample_rich_card();
    card.tts = sample_card().tts;
    card.bgm = sample_card().bgm;
    for face in [&mut card.front, &mut card.back] {
        for block in &mut face.blocks {
            if let ContentBlock::Image { asset: a, .. } = block {
                *a = asset(&media[0]);
            }
        }
    }
    card.front.blocks.push(ContentBlock::Image { asset: asset(&media[0]), alt: "正面".into() });
    card.visual.image = Some(asset(&media[0]));
    card.tts.as_mut().unwrap().audio = asset(&media[1]);
    card.bgm.as_mut().unwrap().track.asset = asset(&media[1]);
    let mut content = sample_deck_pack();
    card.deck_id = content.deck.id.clone();
    content.cards = vec![card];
    PortableDeckPack { version: "2.0".into(), content, media }
}

/// 固定摘要覆盖可选字段，历史缺省仍保持省略。
pub fn sample_access_summary() -> AccessSummary {
    AccessSummary {
        id: "session-a".into(),
        kind: "sessions".into(),
        status: "active".into(),
        tenant_id: Some("workspace".into()),
        label: Some("Example device".into()),
        scopes: Some(vec!["feed:read".into()]),
        scopes_limited: Some(false),
        expires_at: Some(2000000000),
        auth_time: Some(1900000000),
        current: Some(true),
    }
}

/// 新媒体语义单独提供夹具，不改历史缺省示例。
pub fn sample_media_card() -> Card {
    let mut card = sample_card();
    let t = card.tts.as_mut().unwrap();
    t.alignment_quality = Some(AlignmentQuality::Estimated);
    t.audio_kind = Some(AudioKind::Speech);
    t.provenance = Some(ContentProvenance {
        method: "provider".into(),
        provider_claim: Some("espeak-ng".into()),
        ..Default::default()
    });
    let track = &mut card.bgm.as_mut().unwrap().track;
    track.provenance = Some(ContentProvenance {
        method: "manual".into(),
        rights: "CC-BY-4.0".into(),
        attribution: "Example creator".into(),
        sources: vec!["https://example.org/music".into()],
        ..Default::default()
    });
    track.duration_ms = 1000;
    track.loop_start_ms = 0;
    track.loop_end_ms = 1000;
    track.pcm = Some(PcmLoop {
        sample_rate: 8000,
        channels: 2,
        bits_per_sample: 16,
        frames: 8000,
        source_sha256: "0".repeat(64),
        source_start_frame: 100,
        source_end_frame: 8100,
    });
    card
}
