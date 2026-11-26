//! 两库共同验证默认拒绝、用途隔离、CAS、撤回屏障及成员生命周期。
use memoswish_core::{CoreError, Principal};
use memoswish_protocol::{PrivacyPolicy, PrivacyState, PrivacyUpdate};

fn policy() -> PrivacyPolicy {
    memoswish_protocol::examples::sample_privacy_policy()
}
fn update(state: &PrivacyState, kind: &str, version: &str, decision: bool, value: &str) -> PrivacyUpdate {
    PrivacyUpdate {
        expected_revision: state.revision,
        kind: kind.into(),
        version: version.into(),
        decision,
        value: value.into(),
    }
}
async fn ready(repo: &impl memoswish_core::repo::Repository, p: &Principal) -> PrivacyState {
    let mut s = repo.privacy_state(&p.tenant_id, p).await.unwrap();
    for (k, v, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        s = repo.privacy_update(&p.tenant_id, p, &policy(), &update(&s, k, v, true, value)).await.unwrap();
    }
    s
}
async fn suite(repo: &impl memoswish_core::repo::Repository) {
    let p = crate::asset_conformance::seed(repo).await;
    let p = Principal { via: "single_user".into(), ..p };
    let other = crate::asset_conformance::seed(repo).await;
    let other = Principal { via: "single_user".into(), ..other };
    let policy = policy();
    repo.privacy_install_policy(&policy).await.unwrap();
    let user = repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().unwrap();
    let expires = chrono::Utc::now().timestamp() + 3600;
    let client = memoswish_core::oauth::OAuthClient {
        id: memoswish_core::ids::new_id(),
        name: "Privacy OAuth".into(),
        redirect_uris: vec!["https://client.example/cb".into()],
        grant_types: vec!["authorization_code".into()],
        scopes: vec!["content:read".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: expires - 3600,
        expires_at: expires,
    };
    repo.oauth_register(&client).await.unwrap();
    let code = crate::oauth_conformance::code(repo, &user, &client, expires).await;
    let token = crate::oauth_conformance::token(&code, "access");
    assert!(repo.oauth_redeem(&p.tenant_id, &code, std::slice::from_ref(&token), 10).await.unwrap());
    let oauth = Principal {
        via: "mcp_oauth".into(),
        scopes: Some(vec!["content:read".into()]),
        session_access_hash: Some(format!("oauth:{}", token.hash)),
        ..p.clone()
    };
    assert!(repo.oauth_token(&token.hash).await.unwrap().is_some());
    assert!(repo.privacy_admit(&p.tenant_id, &oauth, &policy, Some("external_ai"), None).await.is_err());
    let initial = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    assert_eq!(initial, PrivacyState::default());
    let mut deck = memoswish_protocol::examples::sample_deck();
    deck.id = memoswish_core::ids::new_id();
    deck.card_count = 0;
    let work = memoswish_core::imports::ImportWork {
        result: serde_json::to_value(&deck).unwrap(),
        deck,
        cards: vec![],
        media: vec![],
        auto_tts: false,
        identity_expansion_bytes: 0,
        provenance_expansion_bytes: 0,
    };
    let token_id = memoswish_core::ids::new_id();
    let token_hash = memoswish_core::ids::sha256_hex(token_id.as_bytes());
    let scopes = vec!["*".into()];
    repo.issue_api_token(&memoswish_core::repo::ApiTokenRecord {
        id: token_id,
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        name: "Privacy import".into(),
        token_hash: token_hash.clone(),
        generations: p.credential_generations().unwrap(),
        scopes: scopes.clone(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    let delegated = Principal { via: "api_token".into(), scopes: Some(scopes), ..p.clone() };
    let authority = memoswish_core::imports::ImportAuthority::capture(
        &delegated,
        Some(memoswish_core::imports::ImportCredential { token_hash: Some(token_hash), expires_at: None }),
    );
    let fingerprint = "a".repeat(64);
    assert!(matches!(
        repo.accept_import(&authority, "privacy-import", &fingerprint, &work, None, 2).await,
        Err(CoreError::Forbidden(_))
    ));
    assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, None, None).await.is_err());
    assert!(
        repo.privacy_update(&other.tenant_id, &p, &policy, &update(&initial, "notice", "notice-v1", true, ""))
            .await
            .is_err()
    );
    assert!(
        repo.privacy_update(&p.tenant_id, &p, &policy, &update(&initial, "notice", "unknown", true, "")).await.is_err()
    );
    for (value, decision) in [("unknown", false), ("underage", false)] {
        let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
        repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "age", "notice-v1", decision, value)).await.unwrap();
        assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, None, None).await.is_err());
    }
    let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    assert!(
        repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "age", "notice-v1", true, "unsupported"))
            .await
            .is_err()
    );
    let s = ready(repo, &p).await;
    let operation = repo.accept_import(&authority, "privacy-import", &fingerprint, &work, None, 2).await.unwrap();
    let claim = repo.claim_import(&p.tenant_id, &operation.id, 30_000).await.unwrap().unwrap();
    let underage = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&s, "age", "notice-v1", false, "underage"))
        .await
        .unwrap();
    // 已受理的导入也必须在事务提交时复核收集资格。
    assert!(matches!(repo.commit_import(&p.tenant_id, &claim).await, Err(CoreError::Forbidden(_))));
    repo.fail_import(&p.tenant_id, &claim).await.unwrap();
    let s = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&underage, "age", "notice-v1", true, "example-region"))
        .await
        .unwrap();
    let revision = repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_ai"), None).await.unwrap();
    assert_eq!(revision, s.revision);
    assert!(repo.privacy_admit(&p.tenant_id, &oauth, &policy, Some("external_ai"), None).await.is_ok());
    let generation = repo.membership_join(&p.tenant_id, &other.user_id, memoswish_core::Role::Learner).await.unwrap();
    let member = Principal {
        tenant_id: p.tenant_id.clone(),
        role: memoswish_core::Role::Learner,
        membership_generation: Some(generation),
        ..other.clone()
    };
    assert_eq!(repo.privacy_state(&p.tenant_id, &member).await.unwrap(), PrivacyState::default());
    assert!(repo.privacy_admit(&p.tenant_id, &member, &policy, Some("external_ai"), None).await.is_err());
    assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, Some("research"), None).await.is_err());
    assert!(repo.privacy_admit(&other.tenant_id, &other, &policy, Some("external_ai"), None).await.is_err());
    let mut changed = policy.clone();
    changed.notice_version = "notice-v2".into();
    assert!(repo.privacy_admit(&p.tenant_id, &p, &changed, None, None).await.is_err());
    changed = policy.clone();
    changed.purpose_versions.insert("external_ai".into(), "provider-v2".into());
    assert!(repo.privacy_admit(&p.tenant_id, &p, &changed, Some("external_ai"), None).await.is_err());
    let stale = update(&initial, "terms", "terms-v1", true, "");
    assert!(matches!(repo.privacy_update(&p.tenant_id, &p, &policy, &stale).await, Err(CoreError::Conflict(_))));
    for via in ["api_token", "mcp_oauth"] {
        let delegated = Principal { via: via.into(), scopes: Some(vec!["*".into()]), ..p.clone() };
        assert!(
            repo.privacy_update(
                &p.tenant_id,
                &delegated,
                &policy,
                &update(&s, "external_ai", "provider-policy-v1", true, "")
            )
            .await
            .is_err()
        );
    }
    let withdrawal = update(&s, "external_ai", "provider-policy-v1", false, "");
    let withdrawn = repo.privacy_update(&p.tenant_id, &p, &policy, &withdrawal).await.unwrap();
    assert_eq!(repo.privacy_update(&p.tenant_id, &p, &policy, &withdrawal).await.unwrap(), withdrawn);
    let export =
        repo.export_personal(&memoswish_core::lifecycle::AccountAuthority::Workspace(p.clone())).await.unwrap();
    assert!(serde_json::to_string(&export.privacy_records).unwrap().contains("external_ai"));
    assert!(!serde_json::to_string(&export.privacy_records).unwrap().contains(&other.user_id));
    assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_ai"), None).await.is_err());
    assert!(repo.oauth_token(&token.hash).await.unwrap().is_some());
    assert!(repo.privacy_admit(&p.tenant_id, &oauth, &policy, Some("external_ai"), None).await.is_err());
    let granted = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&withdrawn, "external_ai", "provider-policy-v1", true, ""))
        .await
        .unwrap();
    assert!(granted.revision > revision);
    assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_ai"), Some(revision)).await.is_err());
    assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_ai"), Some(granted.revision)).await.is_ok());
    repo.membership_remove(&p.tenant_id, &p.user_id).await.unwrap();
    assert!(repo.privacy_state(&p.tenant_id, &p).await.is_err());
    let generation = repo.membership_join(&p.tenant_id, &p.user_id, memoswish_core::Role::Owner).await.unwrap();
    let rejoined = Principal { membership_generation: Some(generation), ..p.clone() };
    let state = repo.privacy_state(&p.tenant_id, &rejoined).await.unwrap();
    assert!(state.purpose_records.is_empty());
    assert!(!state.account_records.is_empty());
    assert!(repo.privacy_admit(&p.tenant_id, &rejoined, &policy, Some("external_ai"), None).await.is_err());
    assert_eq!(repo.privacy_state(&other.tenant_id, &other).await.unwrap(), PrivacyState::default());
    repo.transfer_ownership(
        &rejoined,
        &memoswish_core::lifecycle::TransferOwnership { successor_user_id: other.user_id.clone() },
    )
    .await
    .unwrap();
    assert!(repo.privacy_state(&p.tenant_id, &rejoined).await.is_err());
    // 模拟重新交互认证；保留原主体不变，不能把新成员世代补给旧凭据。
    let current = repo.memberships(&p.user_id).await.unwrap().into_iter().find(|m| m.tenant_id == p.tenant_id).unwrap();
    let fresh = Principal { role: current.role, membership_generation: Some(current.generation), ..rejoined };
    repo.close_account_authorized(
        &memoswish_core::lifecycle::AccountAuthority::Workspace(fresh),
        &memoswish_core::lifecycle::CloseAccount::default(),
    )
    .await
    .unwrap();
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_none());
    assert!(repo.privacy_state(&p.tenant_id, &p).await.is_err());
    assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
    assert!(repo.privacy_state(&member.tenant_id, &member).await.is_err());
    assert_eq!(repo.privacy_state(&other.tenant_id, &other).await.unwrap(), PrivacyState::default());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_privacy_state_conformance() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    suite(&repo).await;
    race_and_speech(&repo).await;
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_privacy_state_conformance() {
    crate::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
        let fixture = test.fixture(&url).await;
        let repo = crate::postgres::PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
        suite(&repo).await;
        race_and_speech(&repo).await;
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}

async fn race_and_speech(repo: &impl memoswish_core::repo::Repository) {
    use memoswish_core::tts::*;
    let p = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
    let mut policy = policy();
    policy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
    repo.privacy_install_policy(&policy).await.unwrap();
    let s = ready_with(repo, &p, &policy).await;
    let a = update(&s, "notice", "notice-v1", true, "");
    let b = update(&s, "terms", "terms-v1", true, "");
    let gate = tokio::sync::Barrier::new(2);
    let (a, b) = tokio::join!(
        async {
            gate.wait().await;
            repo.privacy_update(&p.tenant_id, &p, &policy, &a).await
        },
        async {
            gate.wait().await;
            repo.privacy_update(&p.tenant_id, &p, &policy, &b).await
        }
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a, Err(CoreError::Conflict(_))) || matches!(b, Err(CoreError::Conflict(_))));
    let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    let s = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&s, "external_tts", "speech-v1", true, ""))
        .await
        .unwrap();
    let make_work = |revision| SpeechWork {
        provenance: None,
        engine: "test".into(),
        namespace: "config".into(),
        request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
        amount: 3,
        legacy_output: None,
        privacy: Some(memoswish_core::privacy::PrivacyFence {
            principal: p.clone(),
            credential_hash: None,
            policy: policy.clone(),
            revision,
        }),
    };
    let request = repo.accept_speech(&p, &make_work(s.revision), None, Some(100)).await.unwrap();
    let claim = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
    // attempt 先提交，撤回后真实 provider 返回也不能保存字节；费用责任继续保留。
    repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
    let withdrawn = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&s, "external_tts", "speech-v1", false, ""))
        .await
        .unwrap();
    let spec = memoswish_core::assets::AssetSpec {
        mime: "audio/mpeg".into(),
        size: 3,
        sha256: memoswish_core::ids::sha256_hex(b"abc"),
    };
    let meta = SpeechMetadata {
        alignment_quality: None,
        audio_kind: None,
        provenance: None,
        extension: "mp3".into(),
        duration_ms: 100,
        words: vec![],
    };
    assert!(repo.materialize_speech(&p.tenant_id, &claim, b"abc", &spec, &meta, false).await.is_err());
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3, 3));
    let s = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&withdrawn, "external_tts", "speech-v1", true, ""))
        .await
        .unwrap();
    assert!(repo.begin_provider(&p.tenant_id, &claim).await.is_err());
    let request = repo.accept_speech(&p, &make_work(s.revision), None, Some(100)).await.unwrap();
    let claim = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
    // 撤回先提交，下一次 provider attempt 不得产生发送证据。
    repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "external_tts", "speech-v1", false, "")).await.unwrap();
    assert!(repo.begin_provider(&p.tenant_id, &claim).await.is_err());
    // 已 materialize 且 PUT 已返回时撤回，发布仍受同一个修订屏障约束。
    let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    let s = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&s, "external_tts", "speech-v1", true, ""))
        .await
        .unwrap();
    let request = repo.accept_speech(&p, &make_work(s.revision), None, Some(100)).await.unwrap();
    let claim = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
    repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
    repo.materialize_speech(&p.tenant_id, &claim, b"abc", &spec, &meta, false).await.unwrap();
    let (upload, bytes) = repo.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().unwrap();
    assert_eq!(bytes, b"abc");
    let claim = repo.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().unwrap();
    let attempt = repo.begin_upload(&p.tenant_id, &claim, "privacy-store").await.unwrap();
    repo.record_upload(
        &p.tenant_id,
        &attempt,
        &memoswish_core::assets::ObjectVersion::VersionId("exact-version".into()),
    )
    .await
    .unwrap();
    let held = repo.held_speech_usage(&p.tenant_id, &period).await.unwrap();
    repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "external_tts", "speech-v1", false, "")).await.unwrap();
    assert!(repo.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().is_none());
    assert!(repo.publish_speech(&p.tenant_id, &claim, &attempt.id).await.is_err());
    assert!(repo.asset_intent(&p.tenant_id, &upload).await.unwrap().unwrap().published_attempt.is_none());
    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), held);
}
async fn ready_with(
    repo: &impl memoswish_core::repo::Repository,
    p: &Principal,
    policy: &PrivacyPolicy,
) -> PrivacyState {
    let mut s = repo.privacy_state(&p.tenant_id, p).await.unwrap();
    for (kind, version, value) in
        [("notice", "notice-v1", ""), ("terms", "terms-v1", ""), ("age", "notice-v1", "example-region")]
    {
        s = repo.privacy_update(&p.tenant_id, p, policy, &update(&s, kind, version, true, value)).await.unwrap();
    }
    s
}

macro_rules! upgrade {
    ($pool:ty,$migrations:literal) => {
        async fn upgrade(pool:&$pool) {
            let full=sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full,26).run(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO tenants(id,name,plan,created_at) VALUES('privacy-upgrade','Upgrade','free','2026-11-08T00:00:00Z'); INSERT INTO users(id,default_tenant_id,email,display_name,password_hash,created_at) VALUES('privacy-old','privacy-upgrade','privacy-old@example.invalid','Old','preserved-password','2026-11-08T00:00:00Z');").execute(pool).await.unwrap();
            sqlx::query("CREATE TABLE privacy_purposes (invalid TEXT)").execute(pool).await.unwrap();
            assert!(full.run(pool).await.is_err());
            // 第二张表冲突时第一张表和迁移账本一起回滚。
            sqlx::query("CREATE TABLE privacy_accounts (invalid TEXT)").execute(pool).await.unwrap();
            sqlx::query("DROP TABLE privacy_accounts").execute(pool).await.unwrap();
            sqlx::query("DROP TABLE privacy_purposes").execute(pool).await.unwrap();
            full.run(pool).await.unwrap();full.run(pool).await.unwrap();
            assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM privacy_accounts").fetch_one(pool).await.unwrap(),0);
            assert_eq!(sqlx::query_scalar::<_,String>("SELECT password_hash FROM users WHERE id='privacy-old'").fetch_one(pool).await.unwrap(),"preserved-password");
        }
    }
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_privacy_upgrade_rolls_back_without_inventing_evidence() {
    upgrade!(sqlx::SqlitePool, "./migrations/sqlite");
    let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    upgrade(&pool).await;
    pool.close().await;
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_privacy_upgrade_rolls_back_without_inventing_evidence() {
    upgrade!(sqlx::PgPool, "./migrations/postgres");
    crate::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
        let fixture = test.fixture(&url).await;
        let pool =
            sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
        fixture.cleanup().await;
    });
}

struct RetiredSpeech {
    principal: Principal,
    synthesis: String,
    terminal: memoswish_protocol::tts::TtsSubmission,
    held: (i64, i64),
    object: Option<memoswish_core::assets::UploadAttempt>,
}

async fn retire_speech_cases(repo: &impl memoswish_core::repo::Repository) -> Vec<RetiredSpeech> {
    use memoswish_core::{assets::*, tts::*};
    let mut cases = Vec::new();
    for phase in ["before-claim", "after-attempt", "after-put", "restart-before-claim"] {
        let p = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
        let mut policy = policy();
        policy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
        repo.privacy_install_policy(&policy).await.unwrap();
        let state = ready_with(repo, &p, &policy).await;
        let state = repo
            .privacy_update(&p.tenant_id, &p, &policy, &update(&state, "external_tts", "speech-v1", true, ""))
            .await
            .unwrap();
        let mut card = memoswish_protocol::examples::sample_card();
        card.tts = None;
        repo.insert_deck_with_cards(
            &p.tenant_id,
            &memoswish_protocol::examples::sample_deck(),
            std::slice::from_ref(&card),
        )
        .await
        .unwrap();
        let work = SpeechWork {
            provenance: None,
            engine: "test".into(),
            namespace: "privacy-terminal".into(),
            amount: 3,
            legacy_output: None,
            request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
            privacy: Some(memoswish_core::privacy::PrivacyFence {
                principal: p.clone(),
                credential_hash: None,
                policy: policy.clone(),
                revision: state.revision,
            }),
        };
        let accepted = repo
            .submit_speech(
                &p,
                phase,
                &"a".repeat(64),
                &[SpeechSubmissionTarget { card_id: card.id.clone(), revision: card.revision, work }],
                Some(3),
            )
            .await
            .unwrap();
        let request = repo.speech_request(&p.tenant_id, &accepted.items[0].item_id).await.unwrap();
        assert!(!repo.retire_invalid_speech(&p.tenant_id, &request.synthesis_id, &policy, true).await.unwrap());
        let mut object = None;
        let mut upload_claim = None;
        if matches!(phase, "after-attempt" | "after-put") {
            let claim = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
            if phase == "after-put" {
                repo.materialize_speech(
                    &p.tenant_id,
                    &claim,
                    b"abc",
                    &crate::asset_conformance::spec(),
                    &SpeechMetadata {
                        alignment_quality: None,
                        audio_kind: None,
                        provenance: None,
                        extension: "wav".into(),
                        duration_ms: 100,
                        words: vec![],
                    },
                    false,
                )
                .await
                .unwrap();
                let (upload, _) = repo.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().unwrap();
                let claim = repo.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().unwrap();
                let attempt = repo.begin_upload(&p.tenant_id, &claim, "privacy-terminal-store").await.unwrap();
                // 模拟 PUT 已返回而回执尚未写入；撤回后的晚到精确版本仍须保留。
                object = Some(attempt);
                upload_claim = Some(claim);
            }
        }
        let state = repo
            .privacy_update(&p.tenant_id, &p, &policy, &update(&state, "external_tts", "speech-v1", false, ""))
            .await
            .unwrap();
        if phase == "restart-before-claim" {
            // 进程退出前只持久撤回与再授权，终结和额度释放必须由重启后的恢复完成。
            repo.privacy_update(&p.tenant_id, &p, &policy, &update(&state, "external_tts", "speech-v1", true, ""))
                .await
                .unwrap();
            assert_eq!(repo.speech_request(&p.tenant_id, &request.id).await.unwrap().outcome, "pending");
            assert_eq!(
                repo.held_speech_usage(&p.tenant_id, &chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),
                (3, 0)
            );
            let mut terminal = accepted;
            terminal.complete = true;
            terminal.items[0].receipt = Some(memoswish_protocol::tts::TtsAttachmentReceipt {
                item_id: request.id,
                card_id: card.id,
                expected_revision: card.revision,
                disposition: memoswish_protocol::tts::TtsDisposition::Failed,
                resulting_revision: None,
                asset_id: None,
            });
            cases.push(RetiredSpeech {
                principal: p,
                synthesis: request.synthesis_id,
                terminal,
                held: (0, 0),
                object: None,
            });
            continue;
        }
        assert!(repo.retire_invalid_speech(&p.tenant_id, &request.synthesis_id, &policy, true).await.unwrap());
        if let Some(attempt) = &mut object {
            repo.record_upload(&p.tenant_id, attempt, &ObjectVersion::VersionId("exact-late-version".into()))
                .await
                .unwrap();
            *attempt = repo.upload_attempts(&p.tenant_id, &attempt.intent_id).await.unwrap().remove(0);
            assert_eq!(attempt.version, ObjectVersion::VersionId("exact-late-version".into()));
            assert!(repo.publish_speech(&p.tenant_id, upload_claim.as_ref().unwrap(), &attempt.id).await.is_err());
        }
        repo.resolve_speech_attachment(&p.tenant_id, &request.id).await.unwrap();
        let terminal = repo.speech_submission(&p, phase, None).await.unwrap().unwrap();
        assert!(terminal.complete);
        assert_eq!(
            terminal.items[0].receipt.as_ref().unwrap().disposition,
            memoswish_protocol::tts::TtsDisposition::Failed
        );
        assert_eq!(repo.speech_request(&p.tenant_id, &request.id).await.unwrap().outcome, "failed");
        assert!(repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().is_none());
        let held = match phase {
            "before-claim" => (0, 0),
            "after-attempt" => (3, 3),
            _ => (3, 0),
        };
        assert_eq!(
            repo.held_speech_usage(&p.tenant_id, &chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),
            held
        );
        assert!(repo.speech_track(&p.tenant_id, &request.synthesis_id).await.unwrap().is_none());
        assert!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap().tts.is_none());
        // 再授权不能恢复已接受的旧修订，也不能重写终态回执。
        repo.privacy_update(&p.tenant_id, &p, &policy, &update(&state, "external_tts", "speech-v1", true, ""))
            .await
            .unwrap();
        cases.push(RetiredSpeech { principal: p, synthesis: request.synthesis_id, terminal, held, object });
    }
    cases
}

async fn assert_retired_after_restart(repo: &impl memoswish_core::repo::Repository, cases: Vec<RetiredSpeech>) {
    let mut policy = policy();
    policy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
    repo.privacy_install_policy(&policy).await.unwrap();
    for case in cases {
        let p = case.principal;
        assert!(repo.retire_invalid_speech(&p.tenant_id, &case.synthesis, &policy, true).await.unwrap());
        let request_id = &case.terminal.request_id;
        assert_eq!(repo.speech_submission(&p, request_id, None).await.unwrap().unwrap(), case.terminal);
        assert_eq!(
            repo.held_speech_usage(&p.tenant_id, &chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),
            case.held
        );
        assert!(repo.claim_speech(&p.tenant_id, &case.synthesis, 30_000).await.unwrap().is_none());
        if let Some(attempt) = case.object {
            assert_eq!(repo.upload_attempts(&p.tenant_id, &attempt.intent_id).await.unwrap(), vec![attempt]);
        }
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_privacy_terminal_speech_survives_restart() {
    let dir = std::env::temp_dir().join(format!("privacy-terminal-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("test.db").display());
    let repo = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
    let cases = retire_speech_cases(&repo).await;
    repo.pool().close().await;
    let repo = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
    assert_retired_after_restart(&repo, cases).await;
    repo.pool().close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_privacy_terminal_speech_survives_restart() {
    crate::pg_test_support::run_pg_test(|test| async move {
        let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = crate::postgres::PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
        let cases = retire_speech_cases(&repo).await;
        repo.pool().close().await;
        let repo = crate::postgres::PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
        assert_retired_after_restart(&repo, cases).await;
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}

async fn identity_link_privacy(repo: &impl memoswish_core::repo::Repository) {
    use memoswish_core::{CredentialGenerations, ids::new_id};
    let (user, mut identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
    identity.subject = new_id();
    let p = Principal {
        tenant_id: user.tenant_id.clone(),
        user_id: user.id.clone(),
        role: user.role,
        scopes: None,
        via: "single_user".into(),
        session_access_hash: None,
        auth_generation: Some(0),
        membership_generation: Some(0),
        legacy_issued_at: None,
    };
    let template = crate::identity_conformance::claimed_attempt(repo, &identity, true).await;
    let policy = policy();
    repo.privacy_install_policy(&policy).await.unwrap();
    for age in ["unknown", "underage"] {
        let mut blocked = template.clone();
        blocked.id = new_id();
        blocked.state_hash = new_id();
        blocked.launch_hash = new_id();
        if age == "underage" {
            let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
            repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "age", "notice-v1", false, age)).await.unwrap();
        }
        assert!(matches!(repo.identity_attempt_insert(&blocked).await, Err(CoreError::Forbidden(_))));
        assert!(repo.identity_attempt(&blocked.id, false).await.unwrap().is_none());
        assert!(matches!(
            repo.identity_resolve(
                &identity,
                None,
                true,
                None,
                Some(CredentialGenerations { account: 0, membership: 0 }),
                Some(&template.id)
            )
            .await,
            Err(CoreError::Forbidden(_))
        ));
        // 登录仍是已有账户的 bootstrap，不因年龄路由而锁死。
        let login = crate::identity_conformance::claimed_attempt(repo, &identity, false).await;
        assert!(repo.identity_attempt(&login.id, false).await.unwrap().is_some());
    }
    let s = ready_with(repo, &p, &policy).await;
    let before_callback = crate::identity_conformance::claimed_attempt(repo, &identity, true).await;
    let withdrawn = repo
        .privacy_update(&p.tenant_id, &p, &policy, &update(&s, "age", "notice-v1", false, "underage"))
        .await
        .unwrap();
    let generations = CredentialGenerations { account: 0, membership: 0 };
    assert!(matches!(
        repo.identity_resolve(&identity, None, true, None, Some(generations), Some(&before_callback.id)).await,
        Err(CoreError::Forbidden(_))
    ));
    repo.privacy_update(&p.tenant_id, &p, &policy, &update(&withdrawn, "age", "notice-v1", true, "example-region"))
        .await
        .unwrap();
    let pending = crate::identity_conformance::claimed_attempt(repo, &identity, true).await;
    repo.identity_resolve(&identity, None, true, None, Some(generations), Some(&pending.id)).await.unwrap();
    let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "terms", "terms-v1", false, "")).await.unwrap();
    assert!(matches!(
        repo.identity_complete(
            &pending.id,
            &p.tenant_id,
            &p.user_id,
            generations,
            "blocked-link",
            chrono::Utc::now().timestamp()
        )
        .await,
        Err(CoreError::Forbidden(_))
    ));
    assert!(!repo.identity_list(&p.tenant_id, &p.user_id).await.unwrap().iter().any(|i| i.subject == identity.subject));
    assert!(repo.account_export(&p.tenant_id, &p.user_id, true).await.is_ok());
    // 有效资格的新关联成功；撤回后解绑、导出与擦除仍可执行。
    ready_with(repo, &p, &policy).await;
    let fresh = crate::identity_conformance::claimed_attempt(repo, &identity, true).await;
    repo.identity_resolve(&identity, None, true, None, Some(generations), Some(&fresh.id)).await.unwrap();
    repo.identity_complete(
        &fresh.id,
        &p.tenant_id,
        &p.user_id,
        generations,
        "fresh-link",
        chrono::Utc::now().timestamp(),
    )
    .await
    .unwrap();
    let s = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    repo.privacy_update(&p.tenant_id, &p, &policy, &update(&s, "age", "notice-v1", false, "underage")).await.unwrap();
    repo.identity_unlink(
        &p.tenant_id,
        &p.user_id,
        generations,
        &identity.provider,
        "fresh-link",
        chrono::Utc::now().timestamp(),
        &[],
    )
    .await
    .unwrap();
    assert!(repo.identity_list(&p.tenant_id, &p.user_id).await.unwrap().is_empty());
    assert!(repo.account_export(&p.tenant_id, &p.user_id, true).await.is_ok());
    repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_none());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_privacy_identity_link_checks_collection() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    identity_link_privacy(&repo).await;
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_privacy_identity_link_checks_collection() {
    crate::pg_test_support::run_pg_test(|test| async move {
        let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = crate::postgres::PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
        identity_link_privacy(&repo).await;
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}
