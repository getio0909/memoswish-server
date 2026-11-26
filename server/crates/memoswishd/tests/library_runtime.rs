//! 每个场景在独立宿主进程中使用公开 library，避免重置进程生命周期安装锁。

#![cfg(all(feature = "sqlite", unix))]

use std::{future::Future, path::PathBuf, process::Command, time::Duration};

use memoswishd::{Config, Daemon};
use tokio::sync::oneshot;

fn isolated<F, Fut>(name: &str, scenario: F)
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = ()>,
{
    if crate::test_environment::var("MEMOSWISH_E3A_CHILD").as_deref() == Ok(name) {
        let root = PathBuf::from(crate::test_environment::var("MEMOSWISH_E3A_ROOT").unwrap());
        // 宿主预装 subscriber，核心构造不能重新安装全局 subscriber 或嵌套运行时。
        tracing_subscriber::fmt().with_writer(std::io::sink).try_init().unwrap();
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_secs(10), scenario(root)).await.expect("library scenario timed out");
        });
        return;
    }
    let root = std::env::temp_dir().join(format!("memoswish-e3a-{}", memoswish_core::ids::new_id()));
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("MEMOSWISH_E3A_CHILD", name)
        .env("MEMOSWISH_E3A_ROOT", &root)
        .output()
        .unwrap();
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    assert!(
        output.status.success(),
        "child failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn config(root: PathBuf) -> Config {
    let mut config = Config { data_dir: root, seed_demo: false, ..Default::default() };
    config.tts.auto_detect_espeak = false;
    config
}

fn assert_locked(root: &std::path::Path) {
    let competing = std::fs::File::open(root).unwrap();
    assert!(fs4::FileExt::try_lock(&competing).is_err(), "writer/recovery must remain excluded");
}

#[test]
fn startup_rejects_external_writer_before_initializing() {
    isolated("startup_rejects_external_writer_before_initializing", |root| async move {
        std::fs::create_dir(&root).unwrap();
        let writer = std::fs::File::open(&root).unwrap();
        fs4::FileExt::try_lock(&writer).unwrap();
        assert!(Daemon::start(config(root.clone())).await.is_err());
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0, "failed lock must not initialize an installation");
    });
}

#[test]
fn maintenance_requeue_error_retains_process_lock_without_startup() {
    isolated("maintenance_requeue_error_retains_process_lock_without_startup", |root| async move {
        let cfg = config(root.clone());
        assert!(memoswishd::maintenance::requeue_erasure(&cfg, "missing", 0).await.is_err());
        assert_locked(&root);
        assert!(!root.join("jwt_secret").exists());
        assert!(!root.join("assets").exists());
        assert!(Daemon::start(cfg).await.is_err(), "maintenance owns this process's installation");
    });
}

#[test]
fn maintenance_report_success_retains_process_lock_without_startup() {
    isolated("maintenance_report_success_retains_process_lock_without_startup", |root| async move {
        std::fs::create_dir(&root).unwrap();
        let cfg = config(root.clone());
        let repo = memoswish_storage::sqlite::SqliteRepository::connect(&cfg.database_url()).await.unwrap();
        repo.pool().close().await;
        let report = memoswishd::maintenance::content_orphan_report(&cfg).await.unwrap();
        assert!(report.iter().all(|row| row.row_count == 0));
        assert_locked(&root);
        assert!(!root.join("jwt_secret").exists());
        assert!(!root.join("assets").exists());
    });
}

#[test]
fn invalid_configuration_precedes_installation_lock() {
    isolated("invalid_configuration_precedes_installation_lock", |root| async move {
        let mut cfg = config(root.clone());
        cfg.object_store.max_concurrent_puts = 0;
        let error = Daemon::start(cfg).await.err().unwrap();
        assert!(error.to_string().contains("max_concurrent_puts"));
        assert!(!root.exists(), "invalid effective configuration must have zero installation effects");
        // 纯验证失败没有消费进程级锁，修正后可在同一宿主启动。
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        assert_locked(&root);
        daemon.shutdown().await;
    });
}

#[test]
fn post_validation_startup_failure_retains_process_lock() {
    isolated("post_validation_startup_failure_retains_process_lock", |root| async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = config(root.clone());
        cfg.health_bind = listener.local_addr().unwrap().to_string();
        let error = Daemon::start(cfg).await.err().unwrap();
        assert!(error.to_string().contains("cannot bind health listener"));
        assert!(!root.join("learntok.db").exists());
        assert_locked(&root);
        let other = root.join("other");
        assert!(Daemon::start(config(other.clone())).await.is_err());
        assert!(!other.exists(), "second installation must fail before touching its directory");
    });
}

#[test]
fn explicit_shutdown_retains_lock_and_rejects_restart() {
    isolated("explicit_shutdown_retains_lock_and_rejects_restart", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let auth = daemon.services().auth.clone();
        daemon.shutdown().await;
        assert!(operations.spawn(async {}).is_err());
        let error = auth
            .login(&memoswish_protocol::LoginRequest {
                email: "missing@example.com".into(),
                password: "password123".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.http_status(), 503, "all retained auth clones must share closed password admission");
        assert_locked(&root);
        assert!(Daemon::start(config(root.clone())).await.is_err());
        let other = root.join("other");
        assert!(Daemon::start(config(other.clone())).await.is_err());
        assert!(!other.exists());
    });
}

#[test]
fn http_host_routes_preserve_core_auth_and_shutdown_drain() {
    isolated("http_host_routes_preserve_core_auth_and_shutdown_drain", |root| async move {
        let mut cfg = config(root.clone());
        cfg.mode = memoswish_protocol::DeploymentMode::MultiTenant;
        let daemon = Daemon::start(cfg).await.unwrap();
        assert_eq!(daemon.config().data_dir, root);
        assert_eq!(daemon.server_info().mode, memoswish_protocol::DeploymentMode::MultiTenant);
        let operations = daemon.services().operations.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = axum::Router::new().route("/v1/decks", axum::routing::get(|| async { "host route" }));
        let (stop, shutdown) = oneshot::channel();
        let server = tokio::spawn(daemon.serve_http(listener, Some(host), async move { shutdown.await.unwrap() }));
        let client = reqwest::Client::new();
        let base = format!("http://{address}");
        assert_eq!(client.get(format!("{base}/healthz")).send().await.unwrap().text().await.unwrap(), "ok");
        assert_eq!(client.get(format!("{base}/v1/decks")).send().await.unwrap().status(), 401);
        assert_eq!(
            client
                .post(format!("{base}/v1/auth/login"))
                .json(&serde_json::json!({"email":"missing@example.com","password":"password123"}))
                .send()
                .await
                .unwrap()
                .status(),
            401,
            "the connection driver must supply socket peer metadata"
        );
        assert_eq!(
            client.get(format!("{base}/extensions/v1/decks")).send().await.unwrap().text().await.unwrap(),
            "host route"
        );
        stop.send(()).unwrap();
        while let Ok(work) = operations.spawn(async {}) {
            work.await.unwrap();
            tokio::task::yield_now().await;
        }
        assert!(!server.is_finished(), "shutdown must wait for admitted application work");
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        server.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert_locked(&root);
    });
}

#[test]
fn cancelled_http_keeps_drain_owned_by_runtime() {
    isolated("cancelled_http_keeps_drain_owned_by_runtime", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(daemon.serve_http(listener, None, std::future::pending()));
        reqwest::get(format!("http://{address}/healthz")).await.unwrap();
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        while let Ok(work) = operations.spawn(async {}) {
            work.await.unwrap();
            tokio::task::yield_now().await;
        }
        assert!(!work.is_finished());
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        operations.wait().await;
        // 核心取消路径须关闭监听器，而非仅把服务 future 丢弃。
        while tokio::net::TcpStream::connect(address).await.is_ok() {
            tokio::task::yield_now().await;
        }
        assert_locked(&root);
    });
}

#[test]
fn trusted_proxy_and_health_listener_preserve_separate_http_boundaries() {
    isolated("trusted_proxy_and_health_listener_preserve_separate_http_boundaries", |root| async move {
        let health_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let health_address = health_reservation.local_addr().unwrap();
        let mut cfg = config(root);
        cfg.mode = memoswish_protocol::DeploymentMode::MultiTenant;
        cfg.registration_open = true;
        cfg.health_bind = health_address.to_string();
        cfg.proxy_trust.trusted_peers = vec!["127.0.0.1".parse().unwrap()];
        cfg.proxy_trust.normalized_header = Some("x-real-ip".into());
        drop(health_reservation);
        let daemon = Daemon::start(cfg).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(daemon.serve_http(listener, None, async { stopped.await.unwrap() }));
        let client = reqwest::Client::new();
        let base = format!("http://{address}");
        let login = serde_json::json!({"email":"proxy@example.com","password":"password123"});
        assert_eq!(client.post(format!("{base}/v1/auth/login")).json(&login).send().await.unwrap().status(), 400);
        let duplicate = client
            .post(format!("{base}/v1/auth/login"))
            .header("x-real-ip", "192.0.2.1")
            .header("x-real-ip", "192.0.2.2")
            .json(&login)
            .send()
            .await
            .unwrap();
        assert_eq!(duplicate.status(), 400);
        let registered = client
            .post(format!("{base}/v1/auth/register"))
            .header("x-real-ip", "192.0.2.1")
            .json(&serde_json::json!({"email":"proxy@example.com","password":"password123","display_name":"Proxy"}))
            .send()
            .await
            .unwrap();
        assert_eq!(registered.status(), 200);
        assert_eq!(
            client
                .post(format!("{base}/v1/auth/login"))
                .header("x-real-ip", "192.0.2.1")
                .json(&login)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let admin = client.get(format!("{base}/admin")).send().await.unwrap();
        assert!(admin.headers().contains_key("content-security-policy"));
        for path in ["/healthz", "/livez", "/startupz", "/readyz"] {
            let response = client.get(format!("http://{health_address}{path}")).send().await.unwrap();
            assert_eq!(response.status(), 200);
            assert!(!response.headers().contains_key("content-security-policy"));
        }
        for path in ["/admin", "/v1/auth/login", "/mcp"] {
            assert_eq!(client.get(format!("http://{health_address}{path}")).send().await.unwrap().status(), 404);
        }
        let full = client.get(format!("http://{health_address}/metrics")).send().await.unwrap();
        assert_eq!(full.status(), 200);
        assert_eq!(full.headers()[reqwest::header::CONTENT_TYPE], "text/plain; version=0.0.4; charset=utf-8");
        let full = full.text().await.unwrap();
        assert!(full.contains("memoswish_http_responses_total"));
        assert!(full.contains("memoswish_operational_sample_timestamp_seconds"));
        assert!(!full.contains("proxy@example.com"));
        assert!(!full.contains("192.0.2.1"));
        let legacy = client.get(format!("{base}/metrics")).send().await.unwrap().text().await.unwrap();
        assert!(legacy.contains("learntok_http_requests_total"));
        assert!(!legacy.contains("memoswish_http_responses_total"));
        assert!(!legacy.contains("memoswish_operation_duration_seconds"));
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(health_address).await.is_err());
    });
}

#[test]
fn stdio_auth_failure_closes_admission() {
    isolated("stdio_auth_failure_closes_admission", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let error = daemon.serve_stdio(Some("invalid-token"), tokio::io::empty(), tokio::io::sink()).await;
        assert!(error.is_err());
        assert!(operations.spawn(async {}).is_err());
        assert_locked(&root);
    });
}

#[test]
fn premature_drop_closes_admission_without_releasing_lock() {
    isolated("premature_drop_closes_admission_without_releasing_lock", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let auth = daemon.services().auth.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        drop(daemon);
        assert!(operations.spawn(async {}).is_err());
        assert_eq!(
            auth.login(&memoswish_protocol::LoginRequest {
                email: "missing@example.com".into(),
                password: "password123".into(),
            })
            .await
            .unwrap_err()
            .http_status(),
            503
        );
        assert!(!work.is_finished());
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        operations.wait().await;
        assert_locked(&root);
    });
}

struct FailingReader;

impl tokio::io::AsyncRead for FailingReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("synthetic input failure")))
    }
}

#[test]
fn stdio_transport_failure_drains_admitted_work() {
    isolated("stdio_transport_failure_drains_admitted_work", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        let service = tokio::spawn(daemon.serve_stdio(None, FailingReader, tokio::io::sink()));
        while let Ok(work) = operations.spawn(async {}) {
            work.await.unwrap();
            tokio::task::yield_now().await;
        }
        assert!(!service.is_finished(), "handshake failure must await admitted work");
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        let error = service.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("MCP initialization failed"));
        assert_locked(&root);
    });
}

#[test]
fn stdio_eof_drains_admitted_work() {
    isolated("stdio_eof_drains_admitted_work", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        let service = tokio::spawn(daemon.serve_stdio(None, tokio::io::empty(), tokio::io::sink()));
        while let Ok(work) = operations.spawn(async {}) {
            work.await.unwrap();
            tokio::task::yield_now().await;
        }
        assert!(!service.is_finished(), "clean EOF must await admitted work");
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        service.await.unwrap().unwrap();
        assert_locked(&root);
    });
}

#[test]
fn concurrent_start_rejects_losing_installation_before_directory_creation() {
    isolated("concurrent_start_rejects_losing_installation_before_directory_creation", |root| async move {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let starts: Vec<_> = [root.join("a"), root.join("b")]
                .into_iter()
                .map(|directory| {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                        barrier.wait();
                        let started = runtime.block_on(async {
                            match Daemon::start(config(directory.clone())).await {
                                Ok(daemon) => {
                                    daemon.shutdown().await;
                                    true
                                }
                                Err(_) => false,
                            }
                        });
                        (directory, started)
                    })
                })
                .collect();
            starts.into_iter().map(|start| start.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|(_, started)| *started).count(), 1);
        for (directory, started) in results {
            assert_eq!(directory.exists(), started, "losing installation must remain untouched");
            if started {
                assert_locked(&directory);
            }
        }
    });
}

#[test]
fn cancelled_stdio_closes_transport_and_keeps_work_owned() {
    isolated("cancelled_stdio_closes_transport_and_keeps_work_owned", |root| async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        let (client, peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(peer);
        let service = tokio::spawn(daemon.serve_stdio(None, reader, writer));
        let (reader, mut writer) = tokio::io::split(client);
        let mut reader = tokio::io::BufReader::new(reader);
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"host\",\"version\":\"0\"}}}\n").await.unwrap();
        let mut response = String::new();
        assert_ne!(reader.read_line(&mut response).await.unwrap(), 0);
        assert!(serde_json::from_str::<serde_json::Value>(&response).unwrap().get("result").is_some());
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        service.abort();
        assert!(service.await.unwrap_err().is_cancelled());
        while let Ok(work) = operations.spawn(async {}) {
            work.await.unwrap();
            tokio::task::yield_now().await;
        }
        assert!(!work.is_finished());
        response.clear();
        assert_eq!(reader.read_line(&mut response).await.unwrap(), 0, "cancelled host must close MCP transport");
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        operations.wait().await;
        assert_locked(&root);
    });
}

#[test]
fn cancelled_shutdown_wait_keeps_drain_owned_by_runtime() {
    isolated("cancelled_shutdown_wait_keeps_drain_owned_by_runtime", |root| async move {
        let daemon = Daemon::start(config(root.clone())).await.unwrap();
        let operations = daemon.services().operations.clone();
        let (release, pending) = oneshot::channel();
        let work = operations.spawn(async move { pending.await.unwrap() }).unwrap();
        let shutdown = tokio::spawn(daemon.shutdown());
        while let Ok(work) = operations.spawn(async {}) {
            work.await.unwrap();
            tokio::task::yield_now().await;
        }
        shutdown.abort();
        assert!(shutdown.await.unwrap_err().is_cancelled());
        assert!(!work.is_finished());
        assert_locked(&root);
        release.send(()).unwrap();
        work.await.unwrap();
        operations.wait().await;
        assert_locked(&root);
    });
}

#[test]
fn health_listener_observes_draining_and_never_serves_business_routes() {
    isolated("health_listener_observes_draining_and_never_serves_business_routes", |root| async move {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut cfg = config(root.clone());
        cfg.health_bind = address.to_string();
        let daemon = Daemon::start(cfg).await.unwrap();
        let client = reqwest::Client::new();
        let base = format!("http://{address}");
        assert_eq!(client.get(format!("{base}/readyz")).send().await.unwrap().status(), 200);
        assert_eq!(client.get(format!("{base}/v1/server-info")).send().await.unwrap().status(), 404);
        let (release, blocked) = oneshot::channel();
        let (entered, observed) = oneshot::channel();
        daemon
            .services()
            .operations
            .spawn(async move {
                entered.send(()).unwrap();
                let _ = blocked.await;
            })
            .unwrap();
        observed.await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stop, stopped) = oneshot::channel();
        let serving = tokio::spawn(daemon.serve_http(listener, None, async {
            let _ = stopped.await;
        }));
        stop.send(()).unwrap();
        loop {
            let response = client.get(format!("{base}/readyz")).send().await.unwrap();
            if response.status() == 503 {
                assert_eq!(response.text().await.unwrap(), "not_running");
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(client.get(format!("{base}/livez")).send().await.unwrap().status(), 200);
        assert!(!serving.is_finished(), "in-flight durable work must keep the drain owner alive");
        release.send(()).unwrap();
        serving.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert_locked(&root);
    });
}

#[cfg(all(feature = "postgres", feature = "s3", feature = "redis"))]
#[test]
fn migrator_startup_is_observable_and_cancellation_closes_actual_probe_connections() {
    isolated("migrator_startup_is_observable_and_cancellation_closes_actual_probe_connections", |root| async move {
        let database = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut cfg = config(root.clone());
        cfg.profile = memoswishd::deployment::Profile::Horizontal;
        cfg.role = memoswishd::deployment::Role::Migrator;
        cfg.mode = memoswish_protocol::DeploymentMode::MultiTenant;
        cfg.database_url = Some(format!("postgres://synthetic@{}/test", database.local_addr().unwrap()));
        cfg.jwt_secret = Some("synthetic-migrator-key-with-at-least-32-bytes".into());
        cfg.object_store.backend = "s3".into();
        cfg.object_store.s3.access_key_id = "synthetic".into();
        cfg.object_store.s3.secret_access_key = "synthetic".into();
        cfg.admission.backend = "redis".into();
        cfg.admission.redis_url = Some("redis://127.0.0.1:6399".into());
        cfg.health_bind = address.to_string();
        let (stop, stopped) = oneshot::channel();
        let startup = tokio::spawn(Daemon::start_until(cfg, async {
            let _ = stopped.await;
        }));
        // 此处仅有自建 PostgreSQL 握手 mock，不接触共享测试数据库。
        let (_connection, _) = database.accept().await.unwrap();
        let client = reqwest::Client::new();
        let base = format!("http://{address}");
        assert_eq!(client.get(format!("{base}/startupz")).send().await.unwrap().status(), 503);
        assert_eq!(client.get(format!("{base}/readyz")).send().await.unwrap().status(), 503);
        assert_eq!(client.get(format!("{base}/livez")).send().await.unwrap().status(), 200);
        stop.send(()).unwrap();
        let error = startup.await.unwrap().err().unwrap();
        assert_eq!(error.to_string(), "startup cancelled");
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert!(!root.exists(), "horizontal cancelled startup cannot create local installation or key");
    });
}

mod test_environment {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/test-environment.rs"));
}
