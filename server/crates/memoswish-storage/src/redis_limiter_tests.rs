//! Redis 专项夹具只接受独占的临时回环端点，禁止使用系统实例。

use super::*;
use memoswish_core::ids::new_id;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn redis_url() -> String {
    let url = crate::test_environment::var("MEMOSWISH_TEST_REDIS_URL")
        .expect("integration requires MEMOSWISH_TEST_REDIS_URL pointing to an owned throwaway Redis");
    let client = redis::Client::open(url.as_str()).expect("valid test Redis URL");
    assert!(
        matches!(client.get_connection_info().addr(), redis::ConnectionAddr::Tcp(host, port) if host == "127.0.0.1" && *port != 6379),
        "integration requires an owned loopback Redis, never system :6379"
    );
    url
}

fn limiter(url: &str, capacity: u32, refill: f64, timeout: Duration) -> RedisRateLimiter {
    RedisRateLimiter::new(
        url,
        format!("memoswish-test:{}", new_id()),
        AdmissionQuota::new(capacity, refill).unwrap(),
        timeout,
    )
    .unwrap()
}

#[test]
fn different_cost_scales_never_share_a_policy_key() {
    let a = AdmissionQuota::new(u32::MAX, 1_000_000.0).unwrap();
    let b = AdmissionQuota::new(u32::MAX / 3, 1_000_000.0 / 3.0).unwrap();
    assert_eq!(a.burst(), b.burst());
    assert_eq!(a.period(), b.period());
    assert_ne!(a.scale(), b.scale());
    let a = RedisRateLimiter::new("redis://127.0.0.1:6390", "policy-test".into(), a, Duration::from_secs(1)).unwrap();
    let b = RedisRateLimiter::new("redis://127.0.0.1:6390", "policy-test".into(), b, Duration::from_secs(1)).unwrap();
    assert_ne!(a.key("same-tenant"), b.key("same-tenant"));
}

#[tokio::test]
async fn first_connection_failure_is_bounded_and_invalid_cost_does_not_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let limiter = limiter(&format!("redis://{}", listener.local_addr().unwrap()), 1, 1.0, Duration::from_millis(30));
    assert_eq!(limiter.check("a", f64::NAN).await.unwrap_err().http_status(), 400);
    assert!(limiter.connection.read().await.manager.is_none());
    let start = Instant::now();
    assert_eq!(limiter.check("a", 1.0).await.unwrap_err().http_status(), 503);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
#[ignore = "integration: requires MEMOSWISH_TEST_REDIS_URL (owned throwaway Redis)"]
async fn shared_weighted_burst_refill_expiry_namespaces_and_noscript() {
    let url = redis_url();
    let a = limiter(&url, 2, 1.0, Duration::from_secs(2));
    let b = RedisRateLimiter::new(&url, a.prefix.clone(), a.quota, a.timeout).unwrap();
    let (x, y, z) =
        tokio::join!(a.check("work:tenant-a", 1.0), b.check("work:tenant-a", 0.5), a.check("work:tenant-a", 1.0));
    let results = [x, y, z];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 2);
    assert!(results.iter().any(|r| matches!(r, Err(CoreError::QuotaExceeded(_)))));
    b.check("work:tenant-b", 2.0).await.unwrap();
    b.check("auth:tenant-a", 2.0).await.unwrap();
    let mut conn = a.connection().await.unwrap().0;
    let ttl: i64 = redis::cmd("PTTL").arg(a.key("work:tenant-a")).query_async(&mut conn).await.unwrap();
    assert!(ttl > 0 && ttl <= 2000);
    assert!(!a.key("private tenant identifier").contains("private tenant identifier"));
    // 仅临时独占实例允许清空脚本缓存，随后必须由适配器恢复真实准入脚本。
    let _: () = redis::cmd("SCRIPT").arg("FLUSH").query_async(&mut conn).await.unwrap();
    a.check("reload", 0.25).await.unwrap();
    b.check("reload", 1.75).await.unwrap();
    assert!(matches!(a.check("reload", 0.1).await, Err(CoreError::QuotaExceeded(_))));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    a.check("reload", 1.0).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2050)).await;
    let exists: bool = redis::cmd("EXISTS").arg(a.key("reload")).query_async(&mut conn).await.unwrap();
    assert!(!exists);
    b.check("reload", 2.0).await.unwrap();
}

async fn frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        bytes.push(stream.read_u8().await?);
        if bytes.ends_with(b"\r\n") && redis::parse_redis_value(&bytes).is_ok() {
            return Ok(bytes);
        }
    }
}

struct Proxy {
    url: String,
    mode: Arc<AtomicU8>,
    connections: Arc<AtomicUsize>,
    consumed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Proxy {
    async fn new() -> Self {
        let client = redis::Client::open(redis_url()).unwrap();
        let redis::ConnectionAddr::Tcp(host, port) = client.get_connection_info().addr() else {
            panic!("expected TCP");
        };
        let (host, port) = (host.clone(), *port);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let consumed = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let (mode, connections, consumed) = (mode.clone(), connections.clone(), consumed.clone());
            async move {
                let mut sessions = tokio::task::JoinSet::new();
                loop {
                    let (mut downstream, _) = listener.accept().await.unwrap();
                    let index = connections.fetch_add(1, Ordering::SeqCst);
                    let (mode, consumed, host) = (mode.clone(), consumed.clone(), host.clone());
                    sessions.spawn(async move {
                        let mut upstream = TcpStream::connect((host.as_str(), port)).await.unwrap();
                        while let Ok(command) = frame(&mut downstream).await {
                            let redis::Value::Array(args) = redis::parse_redis_value(&command).unwrap() else { panic!("expected RESP command"); };
                            let script = matches!(args.first(), Some(redis::Value::BulkString(name)) if name == b"EVALSHA" || name == b"EVAL");
                            let mode = mode.load(Ordering::SeqCst);
                            if script && mode == 4 { break; }
                            let response = if script && (mode == 2 || (mode == 1 && index == 0)) {
                                b"-READONLY You can't write against a read only replica.\r\n".to_vec()
                            } else {
                                if upstream.write_all(&command).await.is_err() { break; }
                                let Ok(response) = frame(&mut upstream).await else { break; };
                                response
                            };
                            if script && mode == 3 && response == b":1\r\n" {
                                consumed.fetch_add(1, Ordering::SeqCst);
                                std::future::pending::<()>().await;
                            }
                            if downstream.write_all(&response).await.is_err() { break; }
                        }
                    });
                }
            }
        });
        Self { url, mode, connections, consumed, task }
    }
}

#[tokio::test]
#[ignore = "integration: requires MEMOSWISH_TEST_REDIS_URL (owned throwaway Redis)"]
async fn readonly_failover_reconnect_is_coordinated_and_persistent_readonly_bounded() {
    for persistent in [false, true] {
        let proxy = Proxy::new().await;
        let limiter = Arc::new(limiter(&proxy.url, 100, 100.0, Duration::from_millis(500)));
        limiter.check("before", 1.0).await.unwrap();
        proxy.mode.store(if persistent { 2 } else { 1 }, Ordering::SeqCst);
        let start = Instant::now();
        let mut checks = tokio::task::JoinSet::new();
        for n in 0..16 {
            let limiter = limiter.clone();
            checks.spawn(async move { limiter.check(&format!("after-{n}"), 1.0).await });
        }
        while let Some(result) = checks.join_next().await {
            if persistent {
                assert_eq!(result.unwrap().unwrap_err().http_status(), 503);
            } else {
                result.unwrap().unwrap();
            }
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(proxy.connections.load(Ordering::SeqCst), 2);
        if persistent {
            assert_eq!(limiter.check("cooldown", 1.0).await.unwrap_err().http_status(), 503);
            assert_eq!(proxy.connections.load(Ordering::SeqCst), 2);
        }
    }
}

#[tokio::test]
#[ignore = "integration: requires MEMOSWISH_TEST_REDIS_URL (owned throwaway Redis)"]
async fn lost_response_is_not_replayed_and_runtime_failure_policy_preserves_denial() {
    use memoswish_core::rate_limit::{FailureMode, PolicyLimiter};
    let proxy = Proxy::new().await;
    let limiter = Arc::new(limiter(&proxy.url, 1, 0.1, Duration::from_millis(80)));
    limiter.check("warm", 1.0).await.unwrap();
    proxy.mode.store(3, Ordering::SeqCst);
    let start = Instant::now();
    assert_eq!(limiter.check("uncertain", 1.0).await.unwrap_err().http_status(), 503);
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(proxy.consumed.load(Ordering::SeqCst), 1, "a lost response must never trigger a write replay");
    proxy.mode.store(0, Ordering::SeqCst);
    // 从独立连接核实原请求确已消耗令牌，不依赖失去响应的连接恢复时机。
    let direct =
        RedisRateLimiter::new(&redis_url(), limiter.prefix.clone(), limiter.quota, Duration::from_secs(1)).unwrap();
    assert_eq!(direct.check("uncertain", 1.0).await.unwrap_err().http_status(), 429);
    let mut policy = PolicyLimiter {
        backend: Arc::new(direct),
        namespace: "work".into(),
        quota: limiter.quota,
        failure: FailureMode::Open,
    };
    policy.check("denial", 1.0).await.unwrap();
    assert_eq!(policy.check("denial", 1.0).await.unwrap_err().http_status(), 429);
    // 真实已连接后端遇到 READONLY 属于基础设施失败，开放与关闭策略分别生效。
    policy.backend = limiter;
    proxy.mode.store(2, Ordering::SeqCst);
    policy.check("outage", 1.0).await.unwrap();
    policy.failure = FailureMode::Closed;
    assert_eq!(policy.check("outage", 1.0).await.unwrap_err().http_status(), 503);
}

#[tokio::test]
#[ignore = "integration: requires MEMOSWISH_TEST_REDIS_URL (owned throwaway Redis)"]
async fn dropped_connection_recovers_without_replaying_the_failed_call() {
    let proxy = Proxy::new().await;
    let limiter = limiter(&proxy.url, 2, 1.0, Duration::from_millis(500));
    limiter.check("before", 1.0).await.unwrap();
    proxy.mode.store(4, Ordering::SeqCst);
    assert_eq!(limiter.check("disconnected", 1.0).await.unwrap_err().http_status(), 503);
    proxy.mode.store(0, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(600)).await;
    limiter.check("after", 1.0).await.unwrap();
    assert!(proxy.connections.load(Ordering::SeqCst) >= 2);
}
