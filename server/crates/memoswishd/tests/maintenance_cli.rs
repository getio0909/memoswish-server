//! 真实 CLI 子进程复用安装锁；锁冲突必须先于连接、迁移及维护副作用。

#![cfg(all(feature = "sqlite", unix))]

use std::{fs::File, path::PathBuf, process::Command};

use memoswish_core::{
    assets::ObjectVersion,
    erasure::ErasureRepo,
    identity::{ErasureJob, IdentityRepo},
    repo::*,
};
use memoswish_storage::sqlite::SqliteRepository;

struct Installation(PathBuf);

impl Installation {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("memoswish-maintenance-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn cli(&self) -> Command {
        self.cli_for(&self.0)
    }

    fn cli_for(&self, directory: &std::path::Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_memoswishd"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("MEMOSWISH_") {
                command.env_remove(key);
            }
        }
        command.arg("--data-dir").arg(directory);
        command
    }

    fn lock(&self) -> File {
        let file = File::open(&self.0).unwrap();
        fs4::FileExt::try_lock(&file).unwrap();
        file
    }

    fn url(&self) -> String {
        format!("sqlite://{}", self.0.join("learntok.db").display())
    }

    fn assert_no_startup(&self) {
        assert!(!self.0.join("jwt_secret").exists());
        assert!(!self.0.join("assets").exists());
    }
}

impl Drop for Installation {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn assert_locked(output: std::process::Output) {
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("data directory is locked by another writer or recovery operation"), "{error}");
    assert!(output.stdout.is_empty(), "lock failure must not publish a result");
}

#[tokio::test]
async fn retention_and_restore_cli_are_locked_bounded_and_do_not_start_workers() {
    let installation = Installation::new();
    let repo = SqliteRepository::connect(&installation.url()).await.unwrap();
    repo.upsert_tenant(&TenantRecord {
        id: "retention-cli".into(),
        name: "Synthetic".into(),
        plan: "free".into(),
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    let policy = installation.0.join("policy.json");
    std::fs::write(
        &policy,
        r#"{"version":1,"api_metadata_after_expiry_seconds":60,"failed_tts_payload_after_schedule_seconds":60}"#,
    )
    .unwrap();
    let sweep = || {
        installation
            .cli()
            .args(["retention-sweep", "--tenant-id", "retention-cli", "--policy", policy.to_str().unwrap()])
            .output()
            .unwrap()
    };
    let input = installation.0.join("suppressions.json");
    let digest = "a".repeat(64);
    std::fs::write(
        &input,
        serde_json::to_vec(&serde_json::json!({
            "version":1,"snapshot_sha256":digest,"after_sequence":0,"through_sequence":1,
            "entries":[{"sequence":1,"action":{"kind":"delete_workspace","tenant_id":"retention-cli"}}]
        }))
        .unwrap(),
    )
    .unwrap();
    let replay = |snapshot: &str| {
        installation
            .cli()
            .args([
                "restore-suppressions",
                "--input",
                input.to_str().unwrap(),
                "--snapshot-sha256",
                snapshot,
                "--after-sequence",
                "0",
                "--through-sequence",
                "1",
            ])
            .output()
            .unwrap()
    };
    let lock = installation.lock();
    assert_locked(sweep());
    assert_locked(replay(&digest));
    drop(lock);
    let preview = sweep();
    assert!(preview.status.success(), "{}", String::from_utf8_lossy(&preview.stderr));
    assert!(serde_json::from_slice::<serde_json::Value>(&preview.stdout).is_ok());
    assert!(!replay(&"b".repeat(64)).status.success());
    assert!(repo.get_tenant("retention-cli").await.unwrap().is_some());
    for _ in 0..2 {
        let result = replay(&digest);
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    }
    assert!(repo.get_tenant("retention-cli").await.unwrap().is_none());
    assert_eq!(repo.erasure_page("", 100).await.unwrap().len(), 1);
    installation.assert_no_startup();
    repo.pool().close().await;
}

#[test]
fn suppression_cli_rejects_unknown_actions_without_leaking_input_or_creating_database() {
    let installation = Installation::new();
    let input = installation.0.join("invalid.json");
    std::fs::write(&input, r#"{"version":1,"PRIVATE_SENTINEL":"secret","entries":[]}"#).unwrap();
    let result = installation
        .cli()
        .args([
            "restore-suppressions",
            "--input",
            input.to_str().unwrap(),
            "--snapshot-sha256",
            &"a".repeat(64),
            "--after-sequence",
            "0",
            "--through-sequence",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("PRIVATE_SENTINEL"));
    assert!(!installation.0.join("learntok.db").exists());
    installation.assert_no_startup();
}

#[cfg(all(feature = "postgres", feature = "s3", feature = "redis"))]
#[test]
fn horizontal_retention_and_restore_require_maintenance_and_keep_installation_lock() {
    use memoswishd::deployment::{Profile, Role};
    let installation = Installation::new();
    let mut cfg = memoswishd::Config {
        profile: Profile::Horizontal,
        role: Role::Maintenance,
        mode: memoswish_protocol::DeploymentMode::MultiTenant,
        database_url: Some("postgres://127.0.0.1:1/unreachable".into()),
        jwt_secret: Some("synthetic-shared-secret-at-least-32-bytes".into()),
        seed_demo: false,
        ..Default::default()
    };
    cfg.tts.auto_detect_espeak = false;
    cfg.object_store.backend = "s3".into();
    cfg.object_store.s3.access_key_id = "synthetic".into();
    cfg.object_store.s3.secret_access_key = "synthetic".into();
    cfg.admission.backend = "redis".into();
    cfg.admission.redis_url = Some("redis://127.0.0.1:6393".into());
    let config = installation.0.join("horizontal.toml");
    let policy = installation.0.join("policy.json");
    std::fs::write(
        &policy,
        r#"{"version":1,"api_metadata_after_expiry_seconds":60,"failed_tts_payload_after_schedule_seconds":60}"#,
    )
    .unwrap();
    let batch = installation.0.join("batch.json");
    let digest = "a".repeat(64);
    std::fs::write(
        &batch,
        serde_json::to_vec(&serde_json::json!({
            "version":1,"snapshot_sha256":digest,"after_sequence":0,"through_sequence":0,"entries":[]
        }))
        .unwrap(),
    )
    .unwrap();
    let lock = installation.lock();
    for role in [Role::Api, Role::Worker, Role::Migrator, Role::Maintenance] {
        cfg.role = role;
        std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
        for args in [
            vec!["retention-sweep", "--tenant-id", "synthetic", "--policy", policy.to_str().unwrap()],
            vec!["retention-register", "--tenant-id", "synthetic", "--policy", policy.to_str().unwrap()],
            vec![
                "restore-suppressions",
                "--input",
                batch.to_str().unwrap(),
                "--snapshot-sha256",
                &digest,
                "--after-sequence",
                "0",
                "--through-sequence",
                "0",
            ],
        ] {
            let output = installation.cli().arg("--config").arg(&config).args(args).output().unwrap();
            if role == Role::Maintenance {
                assert_locked(output);
            } else {
                assert!(!output.status.success());
                assert!(String::from_utf8_lossy(&output.stderr).contains("requires maintenance role"));
                assert!(output.stdout.is_empty());
            }
        }
    }
    installation.assert_no_startup();
    drop(lock);
}

#[tokio::test]
async fn retention_and_restore_do_not_migrate_stale_schema_or_accept_unknown_policy_fields() {
    let installation = Installation::new();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(installation.url().parse::<sqlx::sqlite::SqliteConnectOptions>().unwrap().create_if_missing(true))
        .await
        .unwrap();
    let full = sqlx::migrate!("../memoswish-storage/migrations/sqlite");
    let old = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(full.iter().filter(|m| m.version < 26).cloned().collect()),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old.run(&pool).await.unwrap();
    let policy = installation.0.join("policy.json");
    let input = installation.0.join("batch.json");
    let digest = "a".repeat(64);
    std::fs::write(
        &policy,
        r#"{"version":1,"api_metadata_after_expiry_seconds":60,"failed_tts_payload_after_schedule_seconds":60}"#,
    )
    .unwrap();
    std::fs::write(
        &input,
        serde_json::to_vec(&serde_json::json!({
            "version":1,"snapshot_sha256":digest,"after_sequence":0,"through_sequence":0,"entries":[]
        }))
        .unwrap(),
    )
    .unwrap();
    for args in [
        vec!["retention-sweep", "--tenant-id", "synthetic", "--policy", policy.to_str().unwrap()],
        vec![
            "restore-suppressions",
            "--input",
            input.to_str().unwrap(),
            "--snapshot-sha256",
            &digest,
            "--after-sequence",
            "0",
            "--through-sequence",
            "0",
        ],
    ] {
        let output = installation.cli().args(args).output().unwrap();
        assert!(!output.status.success());
        let version: i64 =
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(&pool).await.unwrap();
        assert_eq!(version, 25);
    }
    std::fs::write(&policy, r#"{"version":1,"api_metadata_after_expiry_seconds":60,"failed_tts_payload_after_schedule_seconds":60,"PRIVATE_SENTINEL":"secret"}"#).unwrap();
    let output = installation
        .cli()
        .args(["retention-sweep", "--tenant-id", "synthetic", "--policy", policy.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid maintenance input"));
    assert!(!stderr.contains("PRIVATE_SENTINEL"));
    installation.assert_no_startup();
    pool.close().await;
}

#[tokio::test]
async fn old_sqlite_snapshot_cannot_republish_deleted_workspace_after_suppression_replay() {
    let source = Installation::new();
    let restored = Installation::new();
    let repo = SqliteRepository::connect(&source.url()).await.unwrap();
    repo.upsert_tenant(&TenantRecord {
        id: "snapshot-tenant".into(),
        name: "Synthetic".into(),
        plan: "free".into(),
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: "snapshot-owner".into(),
        tenant_id: "snapshot-tenant".into(),
        email: "snapshot@example.invalid".into(),
        display_name: "Owner".into(),
        password_hash: String::new(),
        role: memoswish_core::Role::Owner,
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    let card = memoswish_protocol::examples::sample_card();
    repo.insert_deck("snapshot-tenant", &memoswish_protocol::examples::sample_deck()).await.unwrap();
    repo.insert_card("snapshot-tenant", &card).await.unwrap();
    let object =
        repo.register_managed_put("snapshot-tenant", "original-store", "tenants/snapshot-tenant/object").await.unwrap();
    repo.record_managed_put(&object, &ObjectVersion::VersionId("old-version".into())).await.unwrap();
    // 与 C13 相同的一致快照原语；之后源库擦除不会改变恢复副本。
    sqlx::query("VACUUM INTO $1")
        .bind(restored.0.join("learntok.db").to_str().unwrap())
        .execute(repo.pool())
        .await
        .unwrap();
    // 在恢复库连接打开前计算摘要，避免直接关闭文件描述符释放 SQLite 的 POSIX 锁。
    let digest = memoswish_core::ids::sha256_hex(&std::fs::read(restored.0.join("learntok.db")).unwrap());
    repo.account_erase("snapshot-tenant", "snapshot-owner", true).await.unwrap();
    let copy = SqliteRepository::connect(&restored.url()).await.unwrap();
    assert!(copy.get_card("snapshot-tenant", &card.id).await.unwrap().is_some());
    let input = restored.0.join("replay.json");
    std::fs::write(
        &input,
        serde_json::to_vec(&serde_json::json!({
            "version":1,"snapshot_sha256":digest,"after_sequence":0,"through_sequence":1,
            "entries":[{"sequence":1,"action":{"kind":"delete_workspace","tenant_id":"snapshot-tenant"}}]
        }))
        .unwrap(),
    )
    .unwrap();
    let output = restored
        .cli()
        .args([
            "restore-suppressions",
            "--input",
            input.to_str().unwrap(),
            "--snapshot-sha256",
            &digest,
            "--after-sequence",
            "0",
            "--through-sequence",
            "1",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(copy.get_card("snapshot-tenant", &card.id).await.unwrap().is_none());
    assert!(matches!(copy.insert_card("snapshot-tenant", &card).await, Err(memoswish_core::CoreError::NotFound(_))));
    let pending = copy.erasure_page("", 100).await.unwrap();
    assert_eq!(pending.len(), 1);
    let claim = copy.claim_erasure(&pending[0].job.id, "recovery", 30_000).await.unwrap().unwrap();
    let rejected = copy.complete_erasure(&claim).await.unwrap_err();
    assert!(
        matches!(&rejected, memoswish_core::CoreError::Conflict(message) if message == "erasure external evidence remains unresolved"),
        "{rejected:?}"
    );
    assert_eq!(
        copy.erasure_objects(&claim, ("", ""), 100).await.unwrap()[0].version,
        ObjectVersion::VersionId("old-version".into())
    );
    restored.assert_no_startup();
    repo.pool().close().await;
    copy.pool().close().await;
}

macro_rules! locked_cli {
    ($name:ident, $args:expr) => {
        #[test]
        fn $name() {
            let installation = Installation::new();
            let lock = installation.lock();
            assert_locked(installation.cli().args($args).output().unwrap());
            assert_eq!(std::fs::read_dir(&installation.0).unwrap().count(), 0);
            drop(lock);
        }
    };
}

locked_cli!(default_serve_respects_installation_lock, [] as [&str; 0]);
locked_cli!(serve_respects_installation_lock, ["serve"]);
locked_cli!(stdio_respects_installation_lock, ["mcp-stdio"]);
locked_cli!(token_respects_installation_lock, ["token", "create", "--name", "blocked"]);
locked_cli!(seed_respects_installation_lock, ["seed"]);
#[cfg(feature = "oidc")]
locked_cli!(reencrypt_respects_installation_lock, ["reencrypt-keys"]);
locked_cli!(orphan_report_respects_installation_lock, ["content-orphan-report"]);
locked_cli!(requeue_respects_installation_lock, ["erasure-requeue", "--job-id", "missing", "--expected-revision", "0"]);

#[test]
fn orphan_report_never_creates_a_missing_installation() {
    let installation = Installation::new();
    let absent = installation.0.join("absent");
    let output = installation.cli_for(&absent).arg("content-orphan-report").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot open data directory for locking"));
    assert!(!absent.exists());
}

#[tokio::test]
async fn locked_requeue_preserves_legacy_schema_and_jobs_even_for_invalid_id() {
    let installation = Installation::new();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(installation.url().parse::<sqlx::sqlite::SqliteConnectOptions>().unwrap().create_if_missing(true))
        .await
        .unwrap();
    let full = sqlx::migrate!("../memoswish-storage/migrations/sqlite");
    let old = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(full.iter().filter(|m| m.version < 25).cloned().collect()),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old.run(&pool).await.unwrap();
    let body = serde_json::to_string(&ErasureJob {
        id: "legacy".into(),
        tenant_id: None,
        purge_assets: false,
        credentials: vec![("apple".into(), "SYNTHETIC_CIPHERTEXT".into())],
    })
    .unwrap();
    sqlx::query("INSERT INTO account_erasure_jobs(id,body,drain_until_ms) VALUES('legacy',$1,123)")
        .bind(&body)
        .execute(&pool)
        .await
        .unwrap();
    let lock = installation.lock();
    for id in ["missing", "legacy"] {
        assert_locked(
            installation.cli().args(["erasure-requeue", "--job-id", id, "--expected-revision", "0"]).output().unwrap(),
        );
        let version: i64 =
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(&pool).await.unwrap();
        assert_eq!(version, 24);
        let row: (String, i64) =
            sqlx::query_as("SELECT body,drain_until_ms FROM account_erasure_jobs WHERE id='legacy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row, (body.clone(), 123));
        installation.assert_no_startup();
    }
    drop(lock);
    let report = installation.cli().arg("content-orphan-report").output().unwrap();
    assert!(report.status.success(), "{}", String::from_utf8_lossy(&report.stderr));
    assert!(!String::from_utf8_lossy(&report.stdout).contains("SYNTHETIC_CIPHERTEXT"));
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(&pool).await.unwrap();
    assert_eq!(version, 24, "unlocked diagnostic must remain read-only");
    installation.assert_no_startup();
    pool.close().await;
}

#[tokio::test]
async fn requeue_after_unlock_preserves_revision_budget_and_external_evidence() {
    let installation = Installation::new();
    let repo = SqliteRepository::connect(&installation.url()).await.unwrap();
    repo.upsert_tenant(&TenantRecord {
        id: "erased".into(),
        name: "Erased".into(),
        plan: "free".into(),
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    let object = repo.register_managed_put("erased", "disk-a", "tenants/erased/media").await.unwrap();
    repo.record_managed_put(&object, &ObjectVersion::VersionId("exact-version".into())).await.unwrap();
    sqlx::query("INSERT INTO erased_tenants(tenant_id) VALUES('erased')").execute(repo.pool()).await.unwrap();
    let job = ErasureJob {
        id: "exhausted".into(),
        tenant_id: Some("erased".into()),
        purge_assets: true,
        credentials: vec![("apple".into(), "SYNTHETIC_CIPHERTEXT".into())],
    };
    sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
        .bind(&job.id)
        .bind(serde_json::to_string(&job).unwrap())
        .execute(repo.pool())
        .await
        .unwrap();
    for _ in 0..5 {
        let claim = repo.claim_erasure(&job.id, "exhaust", 30_000).await.unwrap().unwrap();
        let objects = repo.erasure_objects(&claim, ("", ""), 10).await.unwrap();
        repo.begin_erasure_object(&claim, &objects[0], "disk-a").await.unwrap();
        repo.retry_erasure(&claim).await.unwrap();
        // 推进单项业务期限，保留原有耗尽及精确证据断言。
        sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$2 WHERE id=$1 AND kind='erasure'")
            .bind(&job.id)
            .bind(memoswish_core::maintenance::CADENCE_MS)
            .execute(repo.pool())
            .await
            .unwrap();
    }
    let before = repo.erasure_work(&job.id).await.unwrap().unwrap();
    assert_eq!((before.state.as_str(), before.progress.as_str(), before.total_attempts), ("dead", "blocked", 5));
    let evidence_sql = "SELECT store_id,object_key,version_kind,version_id,outcome FROM managed_object_writes";
    let evidence: (String, String, String, String, String) =
        sqlx::query_as(evidence_sql).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(evidence.4, "cleanup_pending");
    let lock = installation.lock();
    let requeue = |revision: i64| {
        installation
            .cli()
            .args(["erasure-requeue", "--job-id", &job.id, "--expected-revision", &revision.to_string()])
            .output()
            .unwrap()
    };
    assert_locked(requeue(before.revision));
    assert_eq!(repo.erasure_work(&job.id).await.unwrap().unwrap().revision, before.revision);
    drop(lock);
    let stale = requeue(before.revision - 1);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("observation is stale"));
    let result = requeue(before.revision);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let after = repo.erasure_work(&job.id).await.unwrap().unwrap();
    assert_eq!((after.state.as_str(), after.progress.as_str(), after.attempts), ("queued", "pending", 0));
    assert_eq!(after.total_attempts, before.total_attempts);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(serde_json::to_value(&after.job).unwrap(), serde_json::to_value(&job).unwrap());
    let retained: (String, String, String, String, String) =
        sqlx::query_as(evidence_sql).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(retained, evidence);
    assert!(repo.account_erased_tenant("erased").await.unwrap());
    assert!(!requeue(before.revision).status.success());
    installation.assert_no_startup();
    repo.claim_erasure(&job.id, "restarted", 30_000).await.unwrap().unwrap();
    assert_eq!(repo.erasure_work(&job.id).await.unwrap().unwrap().total_attempts, 6);
    repo.pool().close().await;
}

#[tokio::test]
async fn password_recovery_cli_requires_stopped_writer_explicit_id_and_protected_stdin() {
    use memoswish_core::password_lifecycle::PasswordLifecycleRepo;
    use std::{io::Write, process::Stdio};
    let installation = Installation::new();
    let repo = SqliteRepository::connect(&installation.url()).await.unwrap();
    let now = chrono::Utc::now();
    repo.upsert_tenant(&TenantRecord {
        id: "recovery".into(),
        name: "Recovery".into(),
        plan: "free".into(),
        created_at: now,
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: "recover-user".into(),
        tenant_id: "recovery".into(),
        email: "recovery@test.invalid".into(),
        display_name: "Recover".into(),
        password_hash: "old-hash".into(),
        role: memoswish_core::Role::Owner,
        created_at: now,
    })
    .await
    .unwrap();
    let call = |id: &str| {
        let mut child = installation
            .cli()
            .args(["password-recover", "--user-id", id])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"new-password-sentinel\n").unwrap();
        child.wait_with_output().unwrap()
    };
    let lock = installation.lock();
    assert_locked(call("recover-user"));
    drop(lock);
    assert!(!call("missing").status.success());
    let output = call("recover-user");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sentinel"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sentinel"));
    let proof = repo.password_snapshot("recovery@test.invalid").await.unwrap().unwrap();
    assert_eq!(proof.generation, 1);
    assert_eq!(proof.version, 1);
    assert!(!proof.verified);
    let runner = memoswish_auth::password::PasswordRunner::new(Default::default()).unwrap();
    assert!(runner.verify("new-password-sentinel", Some(&proof.password_hash)).await.unwrap());
    installation.assert_no_startup();
}

#[tokio::test]
async fn retention_registration_is_explicit_durable_and_does_not_enable_on_preview_or_one_off() {
    let installation = Installation::new();
    let repo = SqliteRepository::connect(&installation.url()).await.unwrap();
    repo.upsert_tenant(&TenantRecord {
        id: "registered".into(),
        name: "Synthetic".into(),
        plan: "free".into(),
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    let policy = installation.0.join("policy.json");
    std::fs::write(
        &policy,
        r#"{"version":1,"api_metadata_after_expiry_seconds":60,"failed_tts_payload_after_schedule_seconds":60}"#,
    )
    .unwrap();
    let command = |verb: &str, apply: bool| {
        let mut cli = installation.cli();
        cli.args([verb, "--tenant-id", "registered", "--policy", policy.to_str().unwrap()]);
        if apply {
            cli.arg("--apply");
        }
        cli.output().unwrap()
    };
    assert!(command("retention-sweep", false).status.success());
    let absent: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_tasks").fetch_one(repo.pool()).await.unwrap();
    assert_eq!(absent, 0);
    let once = command("retention-sweep", true);
    assert!(once.status.success(), "{}", String::from_utf8_lossy(&once.stderr));
    let enabled: i64 = sqlx::query_scalar("SELECT enabled FROM maintenance_tasks WHERE target_tenant='registered'")
        .fetch_one(repo.pool())
        .await
        .unwrap();
    assert_eq!(enabled, 0);
    let before:(String,i64,i64)=sqlx::query_as("SELECT m.cursor,m.cycle,j.available_at_ms FROM maintenance_tasks m JOIN background_jobs j ON j.id=m.id AND j.tenant_id=m.partition_id WHERE m.target_tenant='registered'").fetch_one(repo.pool()).await.unwrap();
    let lock = installation.lock();
    assert_locked(command("retention-register", false));
    drop(lock);
    for _ in 0..2 {
        let out = command("retention-register", false);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let after:(String,i64,i64)=sqlx::query_as("SELECT m.cursor,m.cycle,j.available_at_ms FROM maintenance_tasks m JOIN background_jobs j ON j.id=m.id AND j.tenant_id=m.partition_id WHERE m.target_tenant='registered'").fetch_one(repo.pool()).await.unwrap();
    assert_eq!(before, after);
    let enabled: i64 = sqlx::query_scalar("SELECT enabled FROM maintenance_tasks WHERE target_tenant='registered'")
        .fetch_one(repo.pool())
        .await
        .unwrap();
    assert_eq!(enabled, 1);
    std::fs::write(
        &policy,
        r#"{"version":1,"api_metadata_after_expiry_seconds":61,"failed_tts_payload_after_schedule_seconds":60}"#,
    )
    .unwrap();
    let conflict = command("retention-register", false);
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("differs from durable policy"));
    std::fs::write(&policy, r#"{"version":99,"PRIVATE_SENTINEL":"must-not-leak"}"#).unwrap();
    let invalid = command("retention-register", false);
    assert!(!invalid.status.success());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("PRIVATE_SENTINEL"));
    installation.assert_no_startup();
    repo.pool().close().await;
}
