//! 两库运行同一组生命周期负例、并发单用、撤销及旧凭据快照场景。
use chrono::Utc;
use memoswish_core::{Role, lifecycle::LifecycleRepo, password_lifecycle::*, repo::*, session::*};

async fn setup(repo: &dyn Repository) -> (UserRecord, SessionFamily, SessionCredential) {
    let id = memoswish_core::ids::new_id();
    repo.upsert_tenant(&TenantRecord {
        id: id.clone(),
        name: "Password fixture".into(),
        plan: "free".into(),
        created_at: Utc::now(),
    })
    .await
    .unwrap();
    let u = UserRecord {
        id: memoswish_core::ids::new_id(),
        tenant_id: id.clone(),
        email: format!("{id}@test.invalid"),
        display_name: "Password".into(),
        password_hash: "original-hash".into(),
        role: Role::Owner,
        created_at: Utc::now(),
    };
    repo.insert_user(&u).await.unwrap();
    let f = SessionFamily {
        id: memoswish_core::ids::new_id(),
        user_id: u.id.clone(),
        generation: 0,
        provenance: "password".into(),
        auth_time: Utc::now().timestamp(),
        expires_at: Utc::now().timestamp() + 3600,
        revoked: false,
    };
    let c = SessionCredential {
        access_hash: memoswish_core::ids::new_id(),
        refresh_hash: memoswish_core::ids::new_id(),
        assurance_hash: memoswish_core::ids::new_id(),
        session_id: f.id.clone(),
        tenant_id: None,
        membership_generation: None,
        expires_at: f.expires_at,
    };
    repo.session_issue(&f, &c, None).await.unwrap();
    (u, f, c)
}
async fn run<R: Repository>(repo: &R) {
    let (u, f, c) = setup(repo).await;
    let original = repo.password_snapshot(&u.email).await.unwrap().unwrap();
    assert!(!original.verified);
    assert!(repo.password_challenge(&original, ChallengePurpose::Reset, &"a".repeat(64), 1800).await.is_err());
    repo.password_challenge(&original, ChallengePurpose::Verify, &"a".repeat(64), 1800).await.unwrap();
    // 重发替换，旧邮件即使后到也不能兑换。
    repo.password_challenge(&original, ChallengePurpose::Verify, &"b".repeat(64), 1800).await.unwrap();
    assert!(repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &"a".repeat(64) }).await.is_err());
    assert!(
        repo.password_mutate(PasswordMutation::Reset { email: &u.email, digest: &"b".repeat(64), new_hash: "bad" })
            .await
            .is_err()
    );
    assert!(
        repo.password_mutate(PasswordMutation::Verify { email: "foreign@test.invalid", digest: &"b".repeat(64) })
            .await
            .is_err()
    );
    let d = "b".repeat(64);
    let (a, b) = tokio::join!(
        repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &d }),
        repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &d })
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert!(repo.session_access(&c.access_hash).await.is_ok());
    assert_eq!(repo.account_generation(&u.id).await.unwrap(), 0);
    let verified = repo.password_snapshot(&u.email).await.unwrap().unwrap();
    assert!(verified.verified);
    assert!(repo.password_reset_challenge("unknown@test.invalid", &"9".repeat(64), 1800).await.unwrap().is_none());
    assert_eq!(
        repo.password_reset_challenge(&u.email, &"9".repeat(64), 1800).await.unwrap().as_deref(),
        Some(u.email.as_str())
    );
    repo.password_challenge(&verified, ChallengePurpose::Reset, &"c".repeat(64), 1800).await.unwrap();
    // 消费后的非法写入回滚，不会烧掉可用证明或改变密码。
    assert!(
        repo.password_mutate(PasswordMutation::Reset { email: &u.email, digest: &"c".repeat(64), new_hash: "" })
            .await
            .is_err()
    );
    assert_eq!(repo.password_snapshot(&u.email).await.unwrap().unwrap().password_hash, "original-hash");
    let other = setup(repo).await;
    let token = ApiTokenRecord {
        id: memoswish_core::ids::new_id(),
        tenant_id: u.tenant_id.clone(),
        user_id: u.id.clone(),
        name: "Agent".into(),
        token_hash: memoswish_core::ids::new_id(),
        scopes: vec![],
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
        generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
    };
    repo.issue_api_token(&token).await.unwrap();
    let client = memoswish_core::oauth::OAuthClient {
        id: memoswish_core::ids::new_id(),
        name: "MCP".into(),
        redirect_uris: vec!["https://client.invalid/cb".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["content:read".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: 10,
        expires_at: i64::MAX - 1,
    };
    repo.oauth_register(&client).await.unwrap();
    let code = crate::oauth_conformance::code(repo, &u, &client, f.expires_at).await;
    let access = crate::oauth_conformance::token(&code, "access");
    let refresh = crate::oauth_conformance::token(&code, "refresh");
    assert!(repo.oauth_redeem(&u.tenant_id, &code, &[access.clone(), refresh.clone()], 10).await.unwrap());
    let digest = "c".repeat(64);
    // 重置与改密竞争，只有一个原证明能够提交。
    let (reset, change) = tokio::join!(
        repo.password_mutate(PasswordMutation::Reset { email: &u.email, digest: &digest, new_hash: "reset-hash" }),
        repo.password_mutate(PasswordMutation::Change {
            proof: &verified,
            access_hash: &c.access_hash,
            new_hash: "change-hash"
        })
    );
    assert_ne!(reset.is_ok(), change.is_ok());
    assert_eq!(repo.account_generation(&u.id).await.unwrap(), 1);
    assert_eq!(repo.password_snapshot(&u.email).await.unwrap().unwrap().version, 1);
    assert!(repo.password_proof(&original).await.is_err());
    assert!(repo.session_access(&c.access_hash).await.is_err());
    assert!(repo.session_rotate(&c.refresh_hash, "next-a", "next-r", "next-h", 600).await.is_err());
    assert!(repo.session_issue(&f, &c, None).await.is_err());
    assert!(
        repo.membership_authorize(
            &u.tenant_id,
            &u.id,
            memoswish_core::CredentialGenerations { account: 0, membership: 0 }
        )
        .await
        .is_err()
    );
    assert!(repo.oauth_token(&access.hash).await.unwrap().is_none());
    assert!(
        repo.oauth_rotate(&u.tenant_id, &refresh, &[crate::oauth_conformance::token(&code, "refresh")], 10)
            .await
            .is_err()
    );
    assert!(repo.find_api_token(&token.token_hash).await.unwrap().unwrap().revoked);
    assert!(repo.session_access(&other.2.access_hash).await.is_ok());
    assert_eq!(repo.account_generation(&other.0.id).await.unwrap(), 0);
    assert!(
        repo.password_mutate(PasswordMutation::Reset { email: &u.email, digest: &digest, new_hash: "replay" })
            .await
            .is_err()
    );
    // 运维修复保留账户及成员，但强制重新证明邮箱。
    let current = repo.password_snapshot(&u.email).await.unwrap().unwrap();
    repo.password_mutate(PasswordMutation::Operator { proof: &current, new_hash: "operator-hash" }).await.unwrap();
    let current = repo.password_snapshot(&u.email).await.unwrap().unwrap();
    assert!(!current.verified);
    assert_eq!(current.generation, 2);
    assert!(repo.get_user(&u.tenant_id, &u.id).await.unwrap().is_some());
}

async fn verification_change_interleavings<R: Repository>(repo: &R) {
    for verify_first in [true, false] {
        let (u, _, c) = setup(repo).await;
        let other = setup(repo).await;
        // 捕获改密请求的原始证明，模拟后续哈希期间验证请求提交。
        let proof = repo.password_snapshot(&u.email).await.unwrap().unwrap();
        assert!(!proof.verified);
        let digest = memoswish_core::ids::sha256_hex(u.id.as_bytes());
        repo.password_challenge(&proof, ChallengePurpose::Verify, &digest, 1800).await.unwrap();
        if verify_first {
            repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &digest }).await.unwrap();
            let current = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            assert!(current.verified);
            assert_eq!(current.version, proof.version);
            assert_eq!(current.generation, proof.generation);
        }
        repo.password_mutate(PasswordMutation::Change {
            proof: &proof,
            access_hash: &c.access_hash,
            new_hash: "changed-hash",
        })
        .await
        .unwrap();
        let current = repo.password_snapshot(&u.email).await.unwrap().unwrap();
        assert_eq!(current.verified, verify_first);
        assert_eq!(current.password_hash, "changed-hash");
        assert_eq!(current.version, proof.version + 1);
        assert_eq!(current.generation, proof.generation + 1);
        // 改密先提交时，旧验证挑战不得升级新口令；两种顺序均保持单用和会话撤销。
        assert!(repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &digest }).await.is_err());
        assert!(repo.password_proof(&proof).await.is_err());
        assert!(repo.session_access(&c.access_hash).await.is_err());
        assert!(repo.session_access(&other.2.access_hash).await.is_ok());
        let reset_digest = memoswish_core::ids::sha256_hex(other.0.id.as_bytes());
        assert_eq!(repo.password_reset_challenge(&u.email, &reset_digest, 1800).await.unwrap().is_some(), verify_first);
        // 本机运维修复仍显式清除验证权威。
        repo.password_mutate(PasswordMutation::Operator { proof: &current, new_hash: "operator-hash" }).await.unwrap();
        assert!(!repo.password_snapshot(&u.email).await.unwrap().unwrap().verified);
    }
}

macro_rules! backend_cases {
    ($repo:ty,$clock:expr,$fail:expr,$drop:expr) => {
        async fn rollback_and_restore(repo: &$repo) {
            let (u, _, credential) = setup(repo).await;
            let proof = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            repo.password_challenge(&proof, ChallengePurpose::Verify, &"a".repeat(64), 1800).await.unwrap();
            repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &"a".repeat(64) }).await.unwrap();
            let proof = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            repo.password_challenge(&proof, ChallengePurpose::Reset, &"b".repeat(64), 1800).await.unwrap();
            sqlx::raw_sql($fail).execute(repo.pool()).await.unwrap();
            assert!(
                repo.password_mutate(PasswordMutation::Reset {
                    email: &u.email,
                    digest: &"b".repeat(64),
                    new_hash: "next-hash"
                })
                .await
                .is_err()
            );
            let current = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            assert_eq!(current.password_hash, proof.password_hash);
            assert_eq!(current.generation, proof.generation);
            assert!(repo.session_access(&credential.access_hash).await.is_ok());
            sqlx::raw_sql($drop).execute(repo.pool()).await.unwrap();
            repo.password_mutate(PasswordMutation::Reset {
                email: &u.email,
                digest: &"b".repeat(64),
                new_hash: "next-hash",
            })
            .await
            .unwrap();
            let current = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            repo.password_challenge(&current, ChallengePurpose::Reset, &"c".repeat(64), 1800).await.unwrap();
            let batch = crate::restore_suppression::SuppressionBatch {
                version: 1,
                snapshot_sha256: "a".repeat(64),
                after_sequence: 0,
                through_sequence: 1,
                entries: vec![crate::restore_suppression::SuppressionEntry {
                    sequence: 1,
                    action: crate::restore_suppression::Suppression::PasswordSecurity {
                        user_id: u.id.clone(),
                        minimum_generation: 9,
                    },
                }],
            };
            repo.replay_suppressions(&batch).await.unwrap();
            repo.replay_suppressions(&batch).await.unwrap();
            let restored = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            assert!(restored.password_hash.is_empty());
            assert!(!restored.verified);
            assert_eq!(restored.generation, 9);
            assert!(
                repo.password_mutate(PasswordMutation::Reset {
                    email: &u.email,
                    digest: &"c".repeat(64),
                    new_hash: "replay"
                })
                .await
                .is_err()
            );
        }
        async fn tampering_and_expiry(repo: &$repo) {
            let (u, _, _) = setup(repo).await;
            let proof = repo.password_snapshot(&u.email).await.unwrap().unwrap();
            for column in ["destination", "generation", "credential_version", "expires_at"] {
                repo.password_challenge(&proof, ChallengePurpose::Verify, &"d".repeat(64), 1800).await.unwrap();
                let sql = match column {
                    "destination" => {
                        "UPDATE password_challenges SET destination='other@test.invalid' WHERE user_id=$1".to_owned()
                    }
                    "expires_at" => format!("UPDATE password_challenges SET expires_at=({}) WHERE user_id=$1", $clock),
                    _ => format!("UPDATE password_challenges SET {column}={column}+1 WHERE user_id=$1"),
                };
                sqlx::query(&sql).bind(&u.id).execute(repo.pool()).await.unwrap();
                assert!(
                    repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &"d".repeat(64) })
                        .await
                        .is_err(),
                    "{column}"
                );
            }
            repo.password_cleanup().await.unwrap();
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_challenges WHERE user_id=$1")
                .bind(&u.id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(n, 0);
            repo.password_challenge(&proof, ChallengePurpose::Verify, &"e".repeat(64), 1800).await.unwrap();
            sqlx::query("DELETE FROM users WHERE id=$1").bind(&u.id).execute(repo.pool()).await.unwrap();
            assert!(
                repo.password_mutate(PasswordMutation::Verify { email: &u.email, digest: &"e".repeat(64) })
                    .await
                    .is_err()
            );
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_challenges WHERE user_id=$1")
                .bind(&u.id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(n, 0);
        }
        async fn password_account_erasure(repo: &$repo) {
            let (u, f, c) = setup(repo).await;
            let (other, _, _) = setup(repo).await;
            for user in [&u, &other] {
                let proof = repo.password_snapshot(&user.email).await.unwrap().unwrap();
                let digest = memoswish_core::ids::sha256_hex(user.id.as_bytes());
                repo.password_challenge(&proof, ChallengePurpose::Verify, &digest, 1800).await.unwrap();
                repo.password_mutate(PasswordMutation::Verify { email: &user.email, digest: &digest }).await.unwrap();
                repo.password_reset_challenge(&user.email, &digest, 1800).await.unwrap().unwrap();
            }
            let principal = memoswish_core::AccountPrincipal {
                session_id: Some(f.id),
                session_access_hash: Some(c.access_hash),
                legacy_issued_at: None,
                user_id: u.id.clone(),
                generation: 0,
            };
            let export = repo
                .export_personal(&memoswish_core::lifecycle::AccountAuthority::Account(principal.clone()))
                .await
                .unwrap();
            let export = serde_json::to_string(&export).unwrap();
            assert!(!export.contains("original-hash"));
            assert!(!export.contains(&memoswish_core::ids::sha256_hex(u.id.as_bytes())));
            repo.close_account(
                &principal,
                &memoswish_core::lifecycle::CloseAccount { confirmed_exclusive_workspaces: vec![u.tenant_id.clone()] },
            )
            .await
            .unwrap();
            for table in ["password_credentials", "password_challenges"] {
                let sql = format!("SELECT COUNT(*) FROM {table} WHERE user_id=$1");
                let erased: i64 = sqlx::query_scalar(&sql).bind(&u.id).fetch_one(repo.pool()).await.unwrap();
                let retained: i64 = sqlx::query_scalar(&sql).bind(&other.id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(erased, 0, "{table}");
                assert_eq!(retained, 1, "{table}");
            }
        }
    };
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    backend_cases!(
        crate::sqlite::SqliteRepository,
        "SELECT CAST(strftime('%s','now') AS BIGINT)",
        "CREATE TRIGGER password_failure BEFORE UPDATE ON password_credentials BEGIN SELECT RAISE(ABORT,'injected password write failure'); END;",
        "DROP TRIGGER password_failure;"
    );
    #[tokio::test]
    async fn sqlite_password_lifecycle_conformance() {
        let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
        run(&repo).await;
        tampering_and_expiry(&repo).await;
        rollback_and_restore(&repo).await;
        password_account_erasure(&repo).await;
    }
    #[tokio::test]
    async fn sqlite_password_verification_change_interleavings() {
        let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
        verification_change_interleavings(&repo).await;
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    backend_cases!(
        crate::postgres::PostgresRepository,
        "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT",
        "CREATE FUNCTION password_failure_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected password write failure'; END $$; CREATE TRIGGER password_failure BEFORE UPDATE ON password_credentials FOR EACH ROW EXECUTE FUNCTION password_failure_fn();",
        "DROP TRIGGER password_failure ON password_credentials; DROP FUNCTION password_failure_fn();"
    );
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_password_lifecycle_conformance() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let repo = fixture.repository(4).await.unwrap();
            run(&repo).await;
            tampering_and_expiry(&repo).await;
            rollback_and_restore(&repo).await;
            password_account_erasure(&repo).await;
            fixture.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_password_verification_change_interleavings() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let repo = fixture.repository(4).await.unwrap();
            verification_change_interleavings(&repo).await;
            fixture.cleanup().await;
        });
    }
}
