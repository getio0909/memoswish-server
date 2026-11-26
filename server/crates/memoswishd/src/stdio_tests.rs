//! stdio EOF 必须在 SDK 返回后继续排空已接收导入，覆盖计量与无在途 PUT 的发布等待。

use base64::{Engine, engine::general_purpose::STANDARD};
use memoswish_core::imports::ImportRepo;
use std::sync::{Arc, Mutex};

use memoswish_auth::{AuthConfig, AuthService, Metric, QuotaPolicy, Unlimited};
use memoswish_content::{ContentService, apkg::ApkgOptions};
use memoswish_core::{
    CoreResult, Principal,
    store::{ObjectStore, StoredObject},
};
use memoswish_protocol::AssetRef;
use memoswish_storage::sqlite::SqliteRepository;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;

use crate::{app::AppState, config::Config};

use crate::tests::{APKG_TEST, apkg_support as support};

#[tokio::test]
async fn s5_stdio_startup_captures_authority_and_session_keeps_revocation_fence() {
    use memoswish_core::{
        CredentialGenerations, Role,
        ids::{LOCAL_TENANT_ID, LOCAL_USER_ID},
    };
    use memoswish_protocol::DeploymentMode;

    for mode in [DeploymentMode::SingleUser, DeploymentMode::MultiTenant] {
        for revoke_account in [false, true] {
            let dir = std::env::temp_dir().join(format!("memoswish-stdio-authority-{}", memoswish_core::ids::new_id()));
            let cfg = Config {
                data_dir: dir.clone(),
                mode,
                seed_demo: true,
                tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
                ..Config::default()
            };
            let st = AppState::build(cfg.clone()).await.unwrap();
            let pool = sqlx::SqlitePool::connect(&cfg.database_url()).await.unwrap();
            sqlx::query("UPDATE account_auth_epochs SET generation=7 WHERE user_id=$1")
                .bind(LOCAL_USER_ID)
                .execute(&pool)
                .await
                .unwrap();
            assert!(st.repo.membership_remove(LOCAL_TENANT_ID, LOCAL_USER_ID).await.unwrap());
            assert_eq!(st.repo.membership_join(LOCAL_TENANT_ID, LOCAL_USER_ID, Role::Admin).await.unwrap(), 1);
            crate::runtime::drain_test_state(&st).await;
            drop(st);
            // 重启从已有非零世代开始，可信 stdio 仍可用于多租户部署，但不能冒充当前 owner。
            let st = AppState::build(cfg.clone()).await.unwrap();
            let p = st.services.auth.authenticate_local_stdio().await.unwrap();
            assert_eq!(p.via, "stdio");
            assert_eq!(p.role, Role::Admin);
            assert_eq!(p.credential_generations().unwrap(), CredentialGenerations { account: 7, membership: 1 });
            if mode == DeploymentMode::MultiTenant {
                assert!(st.services.auth.authenticate(None).await.is_err());
            }
            let (client, peer) = tokio::io::duplex(64 * 1024);
            let (read, write) = tokio::io::split(peer);
            let state = st.clone();
            let task = tokio::spawn(async move { crate::serve_stdio(&state, &p, read, write).await });
            let (read, mut write) = tokio::io::split(client);
            let mut read = BufReader::new(read);
            let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}});
            write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
            let mut line = String::new();
            assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
            assert!(serde_json::from_str::<Value>(&line).unwrap().get("result").is_some());
            write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
            for (id, revoked) in [(2, false), (3, true)] {
                if revoked {
                    if revoke_account {
                        sqlx::query("UPDATE account_auth_epochs SET generation=8 WHERE user_id=$1")
                            .bind(LOCAL_USER_ID)
                            .execute(&pool)
                            .await
                            .unwrap();
                    } else {
                        assert!(st.repo.membership_remove(LOCAL_TENANT_ID, LOCAL_USER_ID).await.unwrap());
                        assert!(st.services.auth.authenticate_local_stdio().await.is_err());
                        assert_eq!(
                            st.repo.membership_join(LOCAL_TENANT_ID, LOCAL_USER_ID, Role::Admin).await.unwrap(),
                            2
                        );
                    }
                }
                let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"feed_preview","arguments":{"limit":1}}});
                write.write_all(format!("{request}\n").as_bytes()).await.unwrap();
                line.clear();
                assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
                let response: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(response["id"], id);
                assert_eq!(response["result"]["isError"], revoked, "{response}");
                let sessions: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2")
                        .bind(LOCAL_TENANT_ID)
                        .bind(LOCAL_USER_ID)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                // 预览不创建学习会话或回执；旧 stdio 主体仍须被拒绝。
                let expected_sessions = 0;
                assert_eq!(sessions, expected_sessions, "revoked stdio must not persist another preview session");
                let receipts: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2")
                        .bind(LOCAL_TENANT_ID)
                        .bind(LOCAL_USER_ID)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert_eq!(receipts, expected_sessions, "preview must not persist receipts");
            }
            write.shutdown().await.unwrap();
            drop(write);
            task.await.unwrap().unwrap();
            crate::runtime::drain_test_state(&st).await;
            drop(st);
            // 新会话可捕获撤销后的当前授权，旧会话没有逐请求补齐世代的机会。
            let st = AppState::build(cfg).await.unwrap();
            let fresh = st.services.auth.authenticate_local_stdio().await.unwrap();
            assert_eq!(fresh.auth_generation, Some(if revoke_account { 8 } else { 7 }));
            assert_eq!(fresh.membership_generation, Some(if revoke_account { 1 } else { 2 }));
            assert!(st.services.preview_feed(&fresh, Some(1), None).await.is_ok());
            crate::runtime::drain_test_state(&st).await;
            pool.close().await;
            crate::runtime::cleanup_test_app(dir, &[&st]).await;
        }
    }
}

#[cfg(unix)]
#[test]
fn stdio_lock_drain_child_rejects_legacy_environment_before_directory_creation() {
    const LEGACY: &str = "LEARNTOK_S28_LOCK_DRAIN_CHILD";
    const CANONICAL: &str = "MEMOSWISH_S28_LOCK_DRAIN_CHILD";
    const SENTINEL: &str = "private-lock-drain-child-sentinel";
    let directory = std::env::temp_dir().join(format!("memoswish-lock-drain-guard-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir(&directory).unwrap();
    let child_directory = directory.join("child");
    for value in ["", SENTINEL] {
        for coexist in [false, true] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "stdio_tests::pre_initialize_eof_retains_process_lock_until_application_drain_finishes",
                    "--nocapture",
                    "--format=terse",
                ])
                .env("TMPDIR", &directory)
                .env(LEGACY, value)
                .env_remove(CANONICAL);
            if coexist {
                command.env(CANONICAL, &child_directory);
            }
            let output = command.output().unwrap();
            assert!(!output.status.success(), "legacy child input must fail");
            let diagnostics =
                format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            assert!(diagnostics.contains(LEGACY) && diagnostics.contains(CANONICAL), "{diagnostics}");
            assert!(!diagnostics.contains(SENTINEL), "legacy value must remain private");
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        }
    }
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn pre_initialize_eof_retains_process_lock_until_application_drain_finishes() {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    use tokio::io::AsyncReadExt;

    const CHILD_DIRECTORY: &str = "MEMOSWISH_S28_LOCK_DRAIN_CHILD";
    crate::test_environment::reject_legacy_environment();
    if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
        let directory = std::path::PathBuf::from(directory);
        crate::directory_lock::acquire(&directory).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let st = AppState::build(Config { data_dir: directory.clone(), seed_demo: false, ..Config::default() })
                .await
                .unwrap();
            let completed = directory.join("completed");
            let operation = st
                .services
                .operations
                .spawn(async move {
                    // 父进程确认排空期间仍持锁之后才放行已接收任务。
                    tokio::io::stdin().read_u8().await.unwrap();
                    std::fs::write(completed, "committed").unwrap();
                })
                .unwrap();
            let principal = Principal::local_owner("stdio");
            let drain = crate::serve_stdio(&st, &principal, tokio::io::empty(), tokio::io::sink());
            tokio::pin!(drain);
            tokio::select! {
                biased;
                _ = &mut drain => panic!("EOF must wait for accepted application work"),
                _ = tokio::task::yield_now() => {},
            }
            assert!(st.services.operations.spawn(async {}).is_err(), "EOF must close application admission");
            println!("S28_DRAINING");
            std::io::stdout().flush().unwrap();
            drain.await.unwrap();
            operation.await.unwrap();
        });
        runtime.shutdown_timeout(std::time::Duration::ZERO);
        return;
    }

    let directory = std::env::temp_dir().join(format!("memoswish-lock-drain-{}", memoswish_core::ids::new_id()));
    // 测试子进程独占静态锁，避免污染同进程中的其他 daemon 测试。
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "stdio_tests::pre_initialize_eof_retains_process_lock_until_application_drain_finishes",
                "--nocapture",
                "--format=terse",
            ])
            .env(CHILD_DIRECTORY, &directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap()).lines();
    assert!(output.by_ref().any(|line| line.unwrap() == "S28_DRAINING"), "child must reach application drain");
    let lock = std::fs::File::open(&directory).unwrap();
    assert!(fs4::FileExt::try_lock(&lock).is_err(), "recovery must remain excluded during application drain");
    assert!(!directory.join("completed").exists());
    child.0.stdin.take().unwrap().write_all(b"x").unwrap();
    assert!(child.0.wait().unwrap().success(), "clean EOF must exit successfully after drain");
    assert_eq!(std::fs::read_to_string(directory.join("completed")).unwrap(), "committed");
    fs4::FileExt::try_lock(&lock).expect("process exit must release the writer lock");
    drop(lock);
    std::fs::remove_dir_all(directory).unwrap();
}

struct AccountingHold {
    entered: Semaphore,
    release: Semaphore,
}

struct HeldQuota {
    inner: Unlimited,
    hold: Option<Arc<AccountingHold>>,
}

#[async_trait::async_trait]
impl QuotaPolicy for HeldQuota {
    fn name(&self) -> &'static str {
        "stdio-eof-test"
    }
    async fn consume(&self, p: &Principal, metric: Metric, amount: u64) -> CoreResult<()> {
        if metric == Metric::CardWrites
            && let Some(hold) = &self.hold
        {
            hold.entered.add_permits(1);
            hold.release.acquire().await.unwrap().forget();
        }
        self.inner.consume(p, metric, amount).await
    }
    async fn card_write_limit(&self, _tenant: &str) -> CoreResult<Option<i64>> {
        if let Some(hold) = &self.hold {
            hold.entered.add_permits(1);
            hold.release.acquire().await.unwrap().forget();
        }
        Ok(None)
    }
    async fn snapshot(&self, p: &Principal) -> CoreResult<memoswish_auth::UsageSnapshot> {
        self.inner.snapshot(p).await
    }
}

struct PublicationHold {
    entered: Semaphore,
    connection: Mutex<Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>>,
    pool: sqlx::SqlitePool,
}

struct HeldStore {
    inner: Arc<dyn ObjectStore>,
    hold: Option<Arc<PublicationHold>>,
}

#[async_trait::async_trait]
impl ObjectStore for HeldStore {
    fn namespace(&self) -> CoreResult<String> {
        self.inner.namespace()
    }
    fn kind(&self) -> &'static str {
        "stdio-eof-test"
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        let asset = self.inner.put(key, bytes, mime).await?;
        if let Some(hold) = &self.hold {
            // 真实受保护 PUT 已返回，取走唯一数据库连接，使后续发布等待而非暂停上传。
            let connection = hold.pool.acquire().await.unwrap();
            *hold.connection.lock().unwrap() = Some(connection);
            hold.entered.add_permits(1);
        }
        Ok(asset)
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.inner.delete(key).await
    }
}

async fn image_apkg() -> Vec<u8> {
    support::zip(vec![
        ("collection.anki2", support::database("basic", "Question<img src='x.png'>\x1fAnswer", &[0]).await),
        ("media", br#"{"0":"x.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ])
}

async fn eof_retains_import(pause_publication: bool) {
    let _guard = APKG_TEST.lock().await;
    let bytes = image_apkg().await;
    for fail_publication in [false, true] {
        let dir = std::env::temp_dir().join(format!("memoswish-stdio-eof-{}", memoswish_core::ids::new_id()));
        let mut st =
            AppState::build(Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() }).await.unwrap();
        let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
        AuthService::new(
            repo.clone(),
            AuthConfig {
                mode: memoswish_protocol::DeploymentMode::SingleUser,
                jwt_secret: "s".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: false,
                default_plan: "self_hosted".into(),
            },
        )
        .unwrap()
        .bootstrap_local()
        .await
        .unwrap();
        if fail_publication {
            sqlx::query("CREATE TRIGGER s28_publication_fail BEFORE INSERT ON decks BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END")
                .execute(repo.pool()).await.unwrap();
        }
        let accounting = Arc::new(AccountingHold { entered: Semaphore::new(0), release: Semaphore::new(0) });
        let publication = Arc::new(PublicationHold {
            entered: Semaphore::new(0),
            connection: Mutex::new(None),
            pool: repo.pool().clone(),
        });
        st.services.quota = Arc::new(HeldQuota {
            inner: Unlimited::metered(repo.clone()),
            hold: (!pause_publication).then(|| accounting.clone()),
        });
        st.services.content = ContentService::new(repo.clone()).with_import_store(Arc::new(HeldStore {
            inner: st.store.clone(),
            hold: pause_publication.then(|| publication.clone()),
        }));
        st.mcp = Arc::new(memoswish_mcp::McpServer::new(st.services.clone()));
        st.store.put("tenants/local/keep.png", vec![1], "image/png").await.unwrap();
        let principal = Principal::local_owner("stdio");
        // 占住另一导入许可，收尾后重新准备成功才证明本次许可已释放。
        let held = st.services.content.prepare_apkg(&principal, bytes.clone(), ApkgOptions::default()).await.unwrap();
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(peer);
        let state = st.clone();
        let task =
            tokio::spawn(
                async move { crate::serve_stdio(&state, &Principal::local_owner("stdio"), read, write).await },
            );
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}});
        write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
        assert!(serde_json::from_str::<Value>(&line).unwrap().get("result").is_some());
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        let encoded = STANDARD.encode(&bytes);
        let request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"deck_import_apkg","arguments":{"apkg_base64":encoded}}});
        write.write_all(format!("{request}\n").as_bytes()).await.unwrap();
        if pause_publication {
            publication.entered.acquire().await.unwrap().forget();
        } else {
            accounting.entered.acquire().await.unwrap().forget();
        }
        // 只在外部 I/O 已过屏障后暂停时钟，直接等待 SDK 自己的 EOF 排空期限。
        tokio::time::pause();
        write.shutdown().await.unwrap();
        drop(write);
        line.clear();
        assert_eq!(read.read_line(&mut line).await.unwrap(), 0, "blocked import cannot reply before SDK drain ends");
        tokio::time::resume();
        // 等待 daemon 真正进入排空，避免把 SDK 退出与 JoinHandle 唤醒之间的瞬间当作证明。
        loop {
            assert!(!task.is_finished(), "daemon must retain accepted application work after SDK EOF");
            let Ok(probe) = st.services.operations.spawn(async {}) else {
                break;
            };
            probe.await.unwrap();
        }
        assert!(!task.is_finished(), "closed application admission must still drain the blocked import");
        // 没有在途 PUT，但应用排空仍应阻止运行时退出。
        if pause_publication {
            assert!(st.put_tasks.shutdown().await);
            drop(publication.connection.lock().unwrap().take());
        } else {
            accounting.release.add_permits(1);
        }
        task.await.unwrap().unwrap();
        assert!(st.services.operations.spawn(async {}).is_err(), "shutdown must close new application admission");
        let recovered =
            st.services.content.prepare_apkg(&principal, bytes.clone(), ApkgOptions::default()).await.unwrap();
        drop((held, recovered));
        assert_eq!(st.services.list_decks(&principal).await.unwrap().len(), usize::from(!fail_publication));
        assert_eq!(
            st.services.list_cards(&principal, None, 10, 0).await.unwrap().len(),
            usize::from(!fail_publication)
        );
        assert_eq!(st.store.list_prefix("tenants/local/").await.unwrap().len(), 2);
        assert!(st.store.exists("tenants/local/keep.png").await.unwrap());
        for metric in [Metric::McpCalls, Metric::CardWrites] {
            assert_eq!(
                st.services
                    .usage(&principal)
                    .await
                    .unwrap()
                    .metrics
                    .iter()
                    .find(|m| m.metric == metric.as_str())
                    .unwrap()
                    .used,
                if fail_publication && metric == Metric::CardWrites { 0 } else { 1 }
            );
        }
        if fail_publication {
            assert_eq!(
                st.services
                    .usage(&principal)
                    .await
                    .unwrap()
                    .metrics
                    .iter()
                    .find(|m| m.metric == "card_writes")
                    .unwrap()
                    .held,
                1
            );
            assert!(!repo.pending_imports(None).await.unwrap().is_empty());
        }
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }
}

#[tokio::test]
async fn stdio_eof_drains_import_held_at_accounting() {
    eof_retains_import(false).await;
}

#[tokio::test]
async fn stdio_eof_drains_import_after_upload_before_publication() {
    eof_retains_import(true).await;
}

#[tokio::test]
async fn http_disconnect_then_shutdown_drains_import_before_closing_put_admission() {
    use axum::{body::Body, http::Request};
    use memoswish_content::apkg::ApkgReport;
    use tower::ServiceExt;

    let _guard = APKG_TEST.lock().await;
    let bytes = image_apkg().await;
    let dir = std::env::temp_dir().join(format!("memoswish-http-drain-{}", memoswish_core::ids::new_id()));
    let mut st =
        AppState::build(Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() }).await.unwrap();
    let accounting = Arc::new(AccountingHold { entered: Semaphore::new(0), release: Semaphore::new(0) });
    st.services.quota =
        Arc::new(HeldQuota { inner: Unlimited::metered(st.repo.clone()), hold: Some(accounting.clone()) });
    st.mcp = Arc::new(memoswish_mcp::McpServer::new(st.services.clone()));
    let app = crate::auth_defenses::test_router(st.clone());
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_import_apkg","arguments":{"apkg_base64":STANDARD.encode(&bytes)}}});
    let request = Request::post("/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(Body::from(request.to_string()))
        .unwrap();
    let request = tokio::spawn(async move { app.oneshot(request).await });
    accounting.entered.acquire().await.unwrap().forget();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let drain = crate::drain_background(&st);
    tokio::pin!(drain);
    tokio::select! {
        biased;
        _ = &mut drain => panic!("accepted HTTP import still owns pending work"),
        _ = tokio::task::yield_now() => {},
    }
    let principal = Principal::local_owner("test");
    let denied: CoreResult<ApkgReport> =
        st.services.import_apkg(&principal, bytes.clone(), ApkgOptions::default()).await;
    assert!(matches!(denied, Err(memoswish_core::CoreError::Unavailable(_))));
    accounting.release.add_permits(1);
    drain.await;
    assert_eq!(st.services.list_decks(&principal).await.unwrap().len(), 1);
    assert_eq!(st.store.list_prefix("tenants/local/").await.unwrap().len(), 1);
    for metric in [Metric::McpCalls, Metric::CardWrites] {
        assert_eq!(
            st.services
                .usage(&principal)
                .await
                .unwrap()
                .metrics
                .iter()
                .find(|m| m.metric == metric.as_str())
                .unwrap()
                .used,
            1
        );
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn authenticated_stdio_imports_replay_with_original_credential_evidence() {
    let _guard = APKG_TEST.lock().await;
    let apkg = STANDARD.encode(support::basic().await);
    for kind in ["api_token", "jwt", "session"] {
        let dir = std::env::temp_dir().join(format!("memoswish-s18-stdio-{}", memoswish_core::ids::new_id()));
        let st = AppState::build(Config {
            data_dir: dir.clone(),
            mode: memoswish_protocol::DeploymentMode::MultiTenant,
            registration_open: true,
            seed_demo: false,
            ..Default::default()
        })
        .await
        .unwrap();
        let registered = st
            .services
            .auth
            .register(&memoswish_protocol::RegisterRequest {
                email: "import@example.com".into(),
                password: "fixture-password".into(),
                display_name: "Importer".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        let owner = st.services.auth.authenticate(Some(&registered.access_token)).await.unwrap();
        let token = match kind {
            "api_token" => {
                st.services.auth.create_api_token(&owner, "stdio", vec!["*".into()], None).await.unwrap().plaintext
            }
            "session" => {
                let account = st
                    .services
                    .auth
                    .login_session(&memoswish_protocol::LoginRequest {
                        email: "import@example.com".into(),
                        password: "fixture-password".into(),
                    })
                    .await
                    .unwrap();
                st.services
                    .auth
                    .select_session_workspace(&account.access_token, &owner.tenant_id)
                    .await
                    .unwrap()
                    .access_token
            }
            _ => registered.access_token,
        };
        let p = st.services.auth.authenticate(Some(&token)).await.unwrap();
        assert_eq!(p.via, kind);
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(peer);
        let state = st.clone();
        let captured = p.clone();
        let task = tokio::spawn(async move { crate::serve_stdio(&state, &captured, read, write).await });
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}});
        write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
        assert!(serde_json::from_str::<Value>(&line).unwrap().get("result").is_some());
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        for (name, args) in [
            (
                "deck_import",
                json!({"pack":memoswish_protocol::examples::sample_deck_pack(),"auto_tts":false,"request_id":"stdio-deckpack"}),
            ),
            ("deck_import_apkg", json!({"apkg_base64":apkg,"request_id":"stdio-apkg"})),
        ] {
            let mut first = None;
            for id in [2, 3] {
                let request =
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}});
                write.write_all(format!("{request}\n").as_bytes()).await.unwrap();
                line.clear();
                assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
                let response: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(response["result"]["isError"], false, "{kind} {name}: {response}");
                if let Some(first) = &first {
                    assert_eq!(&response["result"], first);
                }
                first = Some(response["result"].clone());
            }
        }
        assert_eq!(st.services.list_decks(&p).await.unwrap().len(), 2);
        write.shutdown().await.unwrap();
        drop(write);
        task.await.unwrap().unwrap();
        assert!(st.put_tasks.shutdown().await);
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }
}
