//! PostgreSQL 测试专用 schema 生命周期，与产品代码隔离。

use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    process::Command,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
};

use serde_json::json;
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
use tokio::sync::oneshot;

const TOOL: &str = "learntok-pg-fixture-v1";
const STATEMENT_TIMEOUT_MS: &str = "10000";

/// 测试独占的 schema；必须在 run_pg_test 中创建以等待失败或取消后的清理。
pub struct PgFixture {
    pub(crate) schema: String,
    options: PgConnectOptions,
    stop: Option<oneshot::Sender<()>>,
    finished: oneshot::Receiver<bool>,
}

fn git_output(args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("git is required for PostgreSQL fixture ownership");
    assert!(output.status.success(), "git ownership lookup failed");
    String::from_utf8(output.stdout).expect("git ownership must be UTF-8").trim().to_owned()
}

// 测试入口持有全部清理线程，夹具取消或 panic 不会丢失收尾所有者。
#[derive(Clone, Default)]
pub struct PgTest {
    workers: Arc<Mutex<Vec<CleanupWorker>>>,
}

struct CleanupWorker {
    schema: String,
    handle: thread::JoinHandle<Result<(), sqlx::Error>>,
}

// 词法发现无法推断全部方法或宏；真实夹具在连接前再次核验运行器分组。
fn assert_capacity_group(nextest: bool, group: Option<&str>) {
    assert!(
        !nextest || group == Some("postgres-capacity"),
        "PostgreSQL fixtures under nextest require the postgres-capacity test group"
    );
}

/// 运行 PostgreSQL 测试并在成功、panic 或任务取消后等待全部夹具清理。
pub fn run_pg_test<F: Future<Output = ()>>(test: impl FnOnce(PgTest) -> F) {
    assert!(tokio::runtime::Handle::try_current().is_err(), "PostgreSQL test entry must run outside Tokio");
    let owner = PgTest::default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| runtime.block_on(test(owner.clone()))));
    // 先关闭测试运行时，取消剩余任务并触发其中夹具的非阻塞 Drop。
    drop(runtime);
    let cleaned = owner.drain();
    if let Err(panic) = result {
        resume_unwind(panic);
    }
    assert!(cleaned, "PostgreSQL fixture cleanup failed");
}

impl PgTest {
    fn drain(self) -> bool {
        assert!(tokio::runtime::Handle::try_current().is_err(), "cleanup drain must run outside Tokio");
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        let mut cleaned = true;
        for worker in workers {
            match worker.handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    // 仅保留结构化错误码，避免连接 URI 或凭据进入诊断。
                    let code = error.as_database_error().and_then(|error| error.code());
                    eprintln!(
                        "PostgreSQL fixture worker failed for {} (SQLSTATE {}); check connection capacity, locks and permissions; run pg-fixture-janitor if needed",
                        worker.schema,
                        code.as_deref().unwrap_or("unavailable")
                    );
                    cleaned = false;
                }
                Err(_) => {
                    eprintln!("PostgreSQL fixture worker panicked for {}; run pg-fixture-janitor", worker.schema);
                    cleaned = false;
                }
            }
        }
        cleaned
    }

    /// 创建有所有权标记的独有 schema，不复用其他测试的资源。
    pub async fn fixture(&self, url: &str) -> PgFixture {
        let (fixture, started) = self.start_fixture(url);
        started.await.expect("PostgreSQL fixture initialization failed");
        fixture
    }

    fn start_fixture(&self, url: &str) -> (PgFixture, oneshot::Receiver<()>) {
        assert_capacity_group(
            std::env::var_os("NEXTEST").is_some(),
            std::env::var("NEXTEST_TEST_GROUP").ok().as_deref(),
        );
        let schema = format!("learntok_test_{}", memoswish_core::ids::new_id().replace('-', ""));
        let options = PgConnectOptions::from_str(url).expect("invalid PostgreSQL test URL");
        let worktree = git_output(&["rev-parse", "--show-toplevel"]);
        let branch = git_output(&["rev-parse", "--abbrev-ref", "HEAD"]);
        let (stop, stopped) = oneshot::channel();
        let (ready, started) = oneshot::channel();
        let (finished, completion) = oneshot::channel();
        let worker_options = options.clone();
        let worker_schema = schema.clone();
        let worker = thread::spawn(move || {
            // 独立运行时负责收尾，避免依赖已 panic、取消或关闭的测试运行时。
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("fixture runtime failed")
                .block_on(schema_worker(worker_options, worker_schema, worktree, branch, ready, stopped));
            let _ = finished.send(result.is_ok());
            result
        });
        self.workers.lock().unwrap().push(CleanupWorker { schema: schema.clone(), handle: worker });
        // 在第一个 await 前登记 worker 并装好 guard，初始化取消也会通知独立清理线程。
        let fixture = PgFixture { schema, options, stop: Some(stop), finished: completion };
        (fixture, started)
    }
}

impl PgFixture {
    /// 只在本夹具的 search_path 内迁移并连接仓储，连接仍带清理所需标记。
    pub async fn repository(
        &self,
        max_connections: u32,
    ) -> memoswish_core::CoreResult<crate::postgres::PostgresRepository> {
        crate::postgres::PostgresRepository::connect_with_options(self.options(), max_connections).await
    }

    /// 供跨 crate 的真实 runtime 入口测试连接本夹具，保留 search_path 与资源标记。
    pub fn database_url(&self) -> String {
        use sqlx::ConnectOptions;
        let mut url = self.options().to_url_lossy();
        url.query_pairs_mut()
            .append_pair("options", &format!("-c search_path={}", self.schema))
            .append_pair("application_name", &self.schema);
        url.to_string()
    }

    /// 通知独立清理线程并等待本 schema 回收。
    pub async fn cleanup(mut self) {
        drop(self.stop.take());
        assert!(
            (&mut self.finished).await.expect("fixture cleanup worker failed"),
            "PostgreSQL fixture cleanup failed"
        );
    }

    pub(crate) fn options(&self) -> PgConnectOptions {
        self.options.clone().application_name(&self.schema).options([("search_path", self.schema.as_str())])
    }
}

async fn schema_worker(
    options: PgConnectOptions,
    schema: String,
    worktree: String,
    branch: String,
    ready: oneshot::Sender<()>,
    stopped: oneshot::Receiver<()>,
) -> Result<(), sqlx::Error> {
    let mut conn = PgConnection::connect_with(
        &options.application_name(&format!("{schema}_owner")).options([("statement_timeout", STATEMENT_TIMEOUT_MS)]),
    )
    .await?;
    let (backend_pid, backend_start, created_at): (i32, String, i64) = sqlx::query_as(
        "SELECT pid, backend_start::text, FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint FROM pg_stat_activity WHERE pid=pg_backend_pid()",
    ).fetch_one(&mut conn).await?;
    let metadata = json!({
        "tool": TOOL, "schema": schema, "worktree": worktree, "branch": branch,
        "pid": std::process::id(), "created_at": created_at,
        "backend_pid": backend_pid, "backend_start": backend_start,
    })
    .to_string();
    // 创建与标记原子提交，初始化失败只回滚本次事务。
    let mut tx = conn.begin().await?;
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&mut *tx).await?;
    let comment: String = sqlx::query_scalar("SELECT format('COMMENT ON SCHEMA %I IS %L', $1::text, $2::text)")
        .bind(&schema)
        .bind(metadata)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(&comment).execute(&mut *tx).await?;
    tx.commit().await?;
    let _ = ready.send(());
    let _ = stopped.await;
    // panic 时后台任务可能仍持有事务，先断开本夹具标记的连接以释放锁。
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND usename=current_user AND application_name=$1 AND pid<>pg_backend_pid()")
        .bind(&schema).execute(&mut conn).await?;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&mut conn).await?;
    conn.close().await
}

impl Drop for PgFixture {
    fn drop(&mut self) {
        // 完成由异步 cleanup 或测试入口的 drain 确认，Drop 仅发送通知。
        drop(self.stop.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Stdio};

    #[test]
    fn nextest_capacity_guard_rejects_ungrouped_fixtures() {
        assert_capacity_group(false, None);
        assert_capacity_group(true, Some("postgres-capacity"));
        for group in [None, Some("@global"), Some("other-group")] {
            assert!(catch_unwind(|| assert_capacity_group(true, group)).is_err());
        }
    }

    fn url() -> String {
        crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
            .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL")
    }

    async fn exists(conn: &mut PgConnection, schema: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)")
            .bind(schema)
            .fetch_one(conn)
            .await
            .unwrap()
    }

    fn janitor(schema: &str, apply: bool, age: &str) -> String {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/pg-fixture-janitor");
        let mut command = Command::new(script);
        if apply {
            command.arg("--apply");
        }
        let output = command.env("PG_FIXTURE_SCHEMA", schema).env("PG_FIXTURE_MIN_AGE_SECONDS", age).output().unwrap();
        assert!(output.status.success(), "janitor failed: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stderr).unwrap()
    }

    struct Probe {
        child: Child,
        schema: String,
    }

    impl Probe {
        fn start(mode: &str) -> Self {
            // 同一个测试二进制以临时失败/挂起模式运行，父测试检查真实退出后的数据库状态。
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "pg_test_support::tests::postgres_fixture_probe", "--nocapture"])
                .env("MEMOSWISH_PG_FIXTURE_PROBE", mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut probe = Self { child, schema: String::new() };
            let stdout = probe.child.stdout.take().unwrap();
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if let Some(schema) = line.strip_prefix("FIXTURE_READY ") {
                    probe.schema = schema.to_owned();
                    break;
                }
            }
            assert!(!probe.schema.is_empty(), "probe did not publish its owned schema");
            probe
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn janitor_rejects_unsafe_input_and_redacts_connection_errors() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/pg-fixture-janitor");
        for (key, value) in [
            ("PG_FIXTURE_SCHEMA", "public"),
            ("PG_FIXTURE_MIN_AGE_SECONDS", "0; DROP SCHEMA public"),
            ("PG_FIXTURE_MIN_AGE_SECONDS", "-1"),
        ] {
            let output = Command::new(&script)
                .env("MEMOSWISH_TEST_POSTGRES_URL", "postgres://unused")
                .env_remove("PG_FIXTURE_SCHEMA")
                .env_remove("PG_FIXTURE_MIN_AGE_SECONDS")
                .env(key, value)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
        }
        let output = Command::new(&script).env_remove("MEMOSWISH_TEST_POSTGRES_URL").output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let output = Command::new(&script).arg("--unknown").output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let output = Command::new(&script)
            .env("MEMOSWISH_TEST_POSTGRES_URL", "postgres://synthetic:SECRET_SENTINEL@127.0.0.1:1/missing")
            .env_remove("PG_FIXTURE_SCHEMA")
            .env_remove("PG_FIXTURE_MIN_AGE_SECONDS")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        for bytes in [output.stdout, output.stderr] {
            assert!(!String::from_utf8_lossy(&bytes).contains("SECRET_SENTINEL"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn janitor_classifies_failures_without_retry_or_exposing_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("memoswish-janitor-errors-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let psql = dir.join("psql");
        std::fs::write(
            &psql,
            "#!/bin/sh\nprintf 'call\\n' >> \"$PG_FIXTURE_TEST_CALLS\"\nprintf 'SECRET_SENTINEL\\n'\nprintf '%s\\n' \"$PG_FIXTURE_TEST_ERROR\" >&2\nexit \"$PG_FIXTURE_TEST_EXIT\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&psql, std::fs::Permissions::from_mode(0o700)).unwrap();
        let calls = dir.join("calls");
        let path = std::env::join_paths(
            std::iter::once(dir.clone()).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())),
        )
        .unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/pg-fixture-janitor");
        for (status, error, expected) in [
            (
                2,
                "FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute",
                "capacity exhausted (SQLSTATE 53300)",
            ),
            (2, "FATAL:  sorry, too many clients already", "capacity exhausted (SQLSTATE 53300)"),
            (2, "FATAL:  too many connections for role SECRET_SENTINEL", "capacity exhausted (SQLSTATE 53300)"),
            (3, "ERROR:  53300: SECRET_SENTINEL", "capacity exhausted (SQLSTATE 53300)"),
            (3, "ERROR:  55P03: SECRET_SENTINEL", "failed (SQLSTATE 55P03)"),
            (3, "ERROR:  57014: SECRET_SENTINEL", "failed (SQLSTATE 57014)"),
            (3, "ERROR:  42501: SECRET_SENTINEL", "failed (SQLSTATE 42501)"),
            (3, "ERROR:  42P01: SECRET_SENTINEL", "failed (SQLSTATE 42P01)"),
            (
                2,
                "connection failed: postgres://synthetic:SECRET_SENTINEL@invalid/missing",
                "Check database connectivity and permissions",
            ),
        ] {
            std::fs::write(&calls, "").unwrap();
            let output = Command::new(&script)
                .env("PATH", &path)
                .env("MEMOSWISH_TEST_POSTGRES_URL", "postgres://synthetic:SECRET_SENTINEL@invalid/missing")
                .env_remove("PG_FIXTURE_SCHEMA")
                .env_remove("PG_FIXTURE_MIN_AGE_SECONDS")
                .env("PG_FIXTURE_TEST_CALLS", &calls)
                .env("PG_FIXTURE_TEST_ERROR", error)
                .env("PG_FIXTURE_TEST_EXIT", status.to_string())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains(expected), "{stderr}");
            assert!(!stderr.contains("SECRET_SENTINEL"));
            assert!(output.stdout.is_empty());
            assert_eq!(std::fs::read_to_string(&calls).unwrap(), "call\n", "failure must not be retried");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_fixture_probe() {
        run_pg_test(|test| async move {
            let fixture = test.fixture(&url()).await;
            let mode = crate::test_environment::var("MEMOSWISH_PG_FIXTURE_PROBE");
            if mode.as_deref() == Ok("panic") {
                let options = fixture.options();
                let (ready, started) = oneshot::channel();
                tokio::spawn(async move {
                    // panic 展开时任务仍持有 DDL 事务，guard 必须独立解除锁。
                    let mut conn = PgConnection::connect_with(&options).await.unwrap();
                    let mut tx = conn.begin().await.unwrap();
                    sqlx::query("CREATE TABLE panic_lock_probe (value integer)").execute(&mut *tx).await.unwrap();
                    ready.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                started.await.unwrap();
            }
            let isolation_connection = if mode.as_deref() == Ok("hold") {
                let mut conn = PgConnection::connect_with(&fixture.options()).await.unwrap();
                // 两个独立进程都使用不带 schema 限定的相同表名，验证真实 search_path 隔离。
                sqlx::query("CREATE TABLE isolation_probe(value bigint)").execute(&mut conn).await.unwrap();
                sqlx::query("INSERT INTO isolation_probe VALUES ($1)")
                    .bind(i64::from(std::process::id()))
                    .execute(&mut conn)
                    .await
                    .unwrap();
                Some(conn)
            } else {
                None
            };
            println!("FIXTURE_READY {}", fixture.schema);
            std::io::stdout().flush().unwrap();
            match mode.as_deref() {
                Ok("panic") => panic!("intentional PostgreSQL fixture failure"),
                Ok("hold") => std::future::pending::<()>().await,
                _ => {}
            }
            drop(isolation_connection);
        });
    }

    #[tokio::test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    async fn postgres_fixture_failing_test_cleans_schema() {
        let mut probe = Probe::start("panic");
        let status = probe.child.wait().unwrap();
        assert!(!status.success(), "temporary failing test must fail");
        let mut conn = PgConnection::connect(&url()).await.unwrap();
        assert!(!exists(&mut conn, &probe.schema).await, "test entry must drain cleanup before process exit");
        println!("PASS failing child test exited {status}; schema {} removed", probe.schema);
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_fixture_success_and_cancelled_task_clean_schema() {
        run_pg_test(|test| async move {
            let fixture = test.fixture(&url()).await;
            let schema = fixture.schema.clone();
            fixture.cleanup().await;
            let mut conn = PgConnection::connect(&url()).await.unwrap();
            assert!(!exists(&mut conn, &schema).await);
            let (ready, started) = oneshot::channel();
            let task_test = test.clone();
            let task = tokio::spawn(async move {
                let fixture = task_test.fixture(&url()).await;
                ready.send(fixture.schema.clone()).unwrap();
                std::future::pending::<()>().await;
            });
            let schema = started.await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            // Drop 已通知清理线程，用数据库完成屏障验证取消后的回收。
            while exists(&mut conn, &schema).await {
                tokio::task::yield_now().await;
            }
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_fixture_drop_keeps_sibling_progressing_during_cleanup() {
        run_pg_test(|test| async move {
            let fixture = test.fixture(&url()).await;
            let schema = fixture.schema.clone();
            let mut admin = PgConnection::connect(&url()).await.unwrap();
            sqlx::query(&format!("CREATE TABLE {schema}.cleanup_lock(value integer)"))
                .execute(&mut admin)
                .await
                .unwrap();
            // 未使用夹具 application_name 的观测连接持锁，worker 无权提前解除该屏障。
            let mut blocker = PgConnection::connect(&url()).await.unwrap();
            sqlx::query("BEGIN").execute(&mut blocker).await.unwrap();
            sqlx::query(&format!("LOCK TABLE {schema}.cleanup_lock IN ACCESS SHARE MODE"))
                .execute(&mut blocker)
                .await
                .unwrap();
            let worker_name = format!("{schema}_owner");
            let sibling = tokio::spawn(async move {
                let mut observer = PgConnection::connect(&url()).await.unwrap();
                loop {
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'DROP SCHEMA %')"
                    ).bind(&worker_name).fetch_one(&mut observer).await.unwrap();
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                // 同一单线程运行时上的 sibling 必须能观察到清理受阻并释放锁。
                sqlx::query("ROLLBACK").execute(&mut blocker).await.unwrap();
                true
            });
            drop(fixture);
            assert!(sibling.await.unwrap(), "sibling must progress while cleanup is delayed");
            while exists(&mut admin, &schema).await {
                tokio::task::yield_now().await;
            }
            println!("PASS nonblocking Drop; sibling released delayed cleanup for {schema}");
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_fixture_cancelled_initialization_is_drained() {
        let schema = Arc::new(Mutex::new(String::new()));
        let observed = schema.clone();
        run_pg_test(|test| async move {
            // factory 在等待初始化完成前持有此 guard，取消该等待会走同一 Drop 路径。
            let (fixture, started) = test.start_fixture(&url());
            *observed.lock().unwrap() = fixture.schema.clone();
            drop(started);
            drop(fixture);
        });
        run_pg_test(|_| async move {
            let mut conn = PgConnection::connect(&url()).await.unwrap();
            let schema = schema.lock().unwrap().clone();
            assert!(!exists(&mut conn, &schema).await);
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_fixture_cleans_after_test_runtime_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let test = PgTest::default();
        let fixture = runtime.block_on(test.fixture(&url()));
        let schema = fixture.schema.clone();
        drop(runtime);
        drop(fixture);
        assert!(test.drain());
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let mut conn = PgConnection::connect(&url()).await.unwrap();
            assert!(!exists(&mut conn, &schema).await);
        });
    }

    #[tokio::test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    async fn postgres_fixture_concurrent_processes_and_safe_janitor() {
        let mut first = Probe::start("hold");
        let second = Probe::start("hold");
        assert_ne!(first.schema, second.schema);
        let mut conn = PgConnection::connect(&url()).await.unwrap();
        for (schema, pid) in [(&first.schema, first.child.id()), (&second.schema, second.child.id())] {
            let value: i64 = sqlx::query_scalar(&format!("SELECT value FROM {schema}.isolation_probe"))
                .fetch_one(&mut conn)
                .await
                .unwrap();
            assert_eq!(value, i64::from(pid));
        }
        let comment: String =
            sqlx::query_scalar("SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname=$1")
                .bind(&first.schema)
                .fetch_one(&mut conn)
                .await
                .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&comment).unwrap();
        assert_eq!(metadata["pid"], first.child.id());
        assert!(metadata["worktree"].as_str().unwrap().starts_with('/'));
        assert!(!metadata["branch"].as_str().unwrap().is_empty());
        // 即使指定零保留期，仍必须保留正在运行的两个独立进程。
        janitor(&first.schema, true, "0");
        assert!(exists(&mut conn, &first.schema).await);
        assert!(exists(&mut conn, &second.schema).await);
        first.child.kill().unwrap();
        assert!(!first.child.wait().unwrap().success());
        assert!(exists(&mut conn, &first.schema).await, "abrupt termination must leave identifiable metadata");
        // 断开可见性以真实服务端屏障确认，不使用 sleep 或宽限窗口。
        loop {
            let alive: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name IN ($1,$2))")
                    .bind(format!("{}_owner", first.schema))
                    .bind(&first.schema)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
            if !alive {
                break;
            }
            tokio::task::yield_now().await;
        }
        let future = json!({"created_at": i64::MAX});
        let mut future_metadata = metadata.clone();
        future_metadata["created_at"] = future["created_at"].clone();
        let mut wrong_schema = metadata.clone();
        wrong_schema["schema"] = json!(second.schema);
        for invalid in [
            "unrelated schema".to_owned(),
            "{}".to_owned(),
            "{broken".to_owned(),
            wrong_schema.to_string(),
            future_metadata.to_string(),
        ] {
            let statement: String = sqlx::query_scalar("SELECT format('COMMENT ON SCHEMA %I IS %L',$1::text,$2::text)")
                .bind(&first.schema)
                .bind(invalid)
                .fetch_one(&mut conn)
                .await
                .unwrap();
            sqlx::query(&statement).execute(&mut conn).await.unwrap();
            janitor(&first.schema, true, "0");
            assert!(exists(&mut conn, &first.schema).await, "janitor must preserve unrelated or invalid ownership");
        }
        let statement: String = sqlx::query_scalar("SELECT format('COMMENT ON SCHEMA %I IS %L',$1::text,$2::text)")
            .bind(&first.schema)
            .bind(comment)
            .fetch_one(&mut conn)
            .await
            .unwrap();
        sqlx::query(&statement).execute(&mut conn).await.unwrap();
        janitor(&first.schema, true, "3600");
        assert!(exists(&mut conn, &first.schema).await, "fresh orphan must respect retention");
        assert!(janitor(&first.schema, false, "0").contains(&format!("DRY RUN stale owned schema {}", first.schema)));
        assert!(exists(&mut conn, &first.schema).await);
        let outputs = std::thread::scope(|scope| {
            let first_janitor = scope.spawn(|| janitor(&first.schema, true, "0"));
            let second_janitor = scope.spawn(|| janitor(&first.schema, true, "0"));
            [first_janitor.join().unwrap(), second_janitor.join().unwrap()]
        });
        let removal = format!("REMOVED stale owned schema {}", first.schema);
        assert_eq!(outputs.iter().filter(|output| output.contains(&removal)).count(), 1);
        assert!(!exists(&mut conn, &first.schema).await);
        let value: i64 = sqlx::query_scalar(&format!("SELECT value FROM {}.isolation_probe", second.schema))
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(value, i64::from(second.child.id()), "other process data must survive janitor");
        let second_schema = second.schema.clone();
        drop(second);
        // 强制终止第二个子进程后同样只回收其带标记的 schema。
        loop {
            let alive: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name IN ($1,$2))")
                    .bind(format!("{second_schema}_owner"))
                    .bind(&second_schema)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
            if !alive {
                break;
            }
            tokio::task::yield_now().await;
        }
        janitor(&second_schema, true, "0");
        assert!(!exists(&mut conn, &second_schema).await);
        println!(
            "PASS concurrent schemas {}, {}; abrupt termination metadata and safe janitor verified",
            first.schema, second_schema
        );
    }
}
