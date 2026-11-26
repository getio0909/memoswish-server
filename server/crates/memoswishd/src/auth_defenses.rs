//! 密码入口共用来源、账户及在途预算；代理仅信任明确配置的直接对端。
use crate::{api::ApiErr, app::AppState};
use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use memoswish_core::{CoreError, CoreResult, rate_limit::RateLimiter};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyTrust {
    pub trusted_peers: Vec<IpAddr>,
    pub normalized_header: Option<String>,
}
impl ProxyTrust {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.trusted_peers.len() <= 32, "too many trusted proxy peers");
        anyhow::ensure!(
            self.trusted_peers.is_empty() == self.normalized_header.is_none(),
            "proxy mode requires peers and one normalized header"
        );
        if let Some(name) = &self.normalized_header {
            // 不支持链式转发语法，也不允许复用认证、路由或连接控制头。
            anyhow::ensure!(
                matches!(name.as_str(), "x-real-ip" | "x-learntok-client-ip"),
                "unsupported normalized proxy header"
            );
        }
        Ok(())
    }
    fn source(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> CoreResult<String> {
        let peer = peer.ok_or_else(|| CoreError::Unavailable("socket peer metadata required".into()))?;
        let peer = canonical(peer.ip());
        let ip = if self.trusted_peers.iter().any(|p| canonical(*p) == peer) {
            let name = self
                .normalized_header
                .as_deref()
                .ok_or_else(|| CoreError::Unavailable("invalid proxy configuration".into()))?;
            let mut values = headers.get_all(name).iter();
            let value = values.next().and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<IpAddr>().ok());
            if values.next().is_some() || value.is_none() {
                return Err(CoreError::invalid("one normalized client IP header required"));
            }
            canonical(value.expect("validated IP"))
        } else {
            peer
        };
        // IPv6 同一 /64 共用来源预算，IPv4 映射地址不能绕过 IPv4 预算。
        Ok(match ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("{:x}:64", u128::from(ip) >> 64),
        })
    }
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        _ => ip,
    }
}

// 固定哈希槽使 Redis 与本地状态均有硬上限；碰撞仅保守共享额度。
const SLOTS: usize = 4096;
fn slot(key: &str) -> usize {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(key.as_bytes());
    usize::from(u16::from_be_bytes([hash[0], hash[1]])) % SLOTS
}
pub struct AuthAdmission {
    observer: Arc<dyn memoswish_core::observability::Observer>,
    sources: Arc<dyn RateLimiter>,
    accounts: Arc<dyn RateLimiter>,
    active: Vec<Arc<Semaphore>>,
}
impl AuthAdmission {
    pub fn build(config: &crate::admission::AdmissionConfig) -> anyhow::Result<Self> {
        Self::build_observed(config, memoswish_core::observability::noop())
    }

    pub fn build_observed(
        config: &crate::admission::AdmissionConfig,
        observer: Arc<dyn memoswish_core::observability::Observer>,
    ) -> anyhow::Result<Self> {
        use memoswish_core::rate_limit::FailureMode;
        anyhow::ensure!(config.max_keys >= SLOTS, "authentication admission max_keys must be at least 4096");
        anyhow::ensure!(
            matches!(config.auth_failure, FailureMode::Closed),
            "authentication admission must fail closed"
        );
        Ok(Self {
            sources: crate::admission::build_observed(
                config,
                "password-source",
                20,
                0.2,
                FailureMode::Closed,
                observer.clone(),
            )?,
            accounts: crate::admission::build_observed(
                config,
                "password-account",
                10,
                0.1,
                FailureMode::Closed,
                observer.clone(),
            )?,
            observer,
            active: (0..SLOTS).map(|_| Arc::new(Semaphore::new(1))).collect(),
        })
    }
    #[cfg(test)]
    pub(crate) fn test_backend(backend: Arc<dyn RateLimiter>) -> Self {
        Self {
            observer: memoswish_core::observability::noop(),
            sources: backend.clone(),
            accounts: backend,
            active: (0..SLOTS).map(|_| Arc::new(Semaphore::new(1))).collect(),
        }
    }
    async fn source(&self, source: &str) -> CoreResult<tokio::sync::OwnedSemaphorePermit> {
        let index = slot(source);
        // 在等待共享后端前占有来源容量，单来源不能堆积 Redis 准入请求。
        let permit = self.active[index].clone().try_acquire_owned().map_err(|_| {
            self.observer.admission(
                memoswish_core::observability::AdmissionClass::PasswordSource,
                memoswish_core::observability::AdmissionOutcome::Rejected,
            );
            CoreError::QuotaExceeded("source authentication work busy".into())
        })?;
        // 调用方取消后，共享后端检查仍在既有总期限内持有同一来源容量。
        let backend = self.sources.clone();
        tokio::spawn(async move {
            backend.check(&index.to_string(), 1.0).await?;
            Ok(permit)
        })
        .await
        .map_err(|_| CoreError::Unavailable("source admission worker failed".into()))?
    }
    async fn account(&self, email: &str) -> CoreResult<()> {
        self.accounts.check(&slot(email).to_string(), 1.0).await
    }
}

pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if req.method() != Method::POST
        || !matches!(
            req.uri().path(),
            "/v1/auth/register"
                | "/v1/auth/login"
                | "/v1/auth/account-sessions"
                | "/v1/auth/sessions"
                | "/v1/auth/sessions/register"
                | "/v1/auth/password/verification"
                | "/v1/auth/password/verification/resend"
                | "/v1/auth/password/verification/confirm"
                | "/v1/auth/password/reset"
                | "/v1/auth/password/reset/confirm"
                | "/v1/account/password"
                | "/oauth/login"
        )
    {
        return next.run(req).await;
    }
    let password_lifecycle = req.uri().path().contains("/password");
    let account_password = req.uri().path() == "/v1/account/password";
    let oauth = req.uri().path() == "/oauth/login";
    if oauth && !state.config.oauth.enabled {
        return next.run(req).await;
    }
    let result = async {
        let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|p| p.0);
        let source = state.config.proxy_trust.source(peer, req.headers())?;
        let permit = state.auth_admission.source(&source).await?;
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body, 16 * 1024).await.map_err(|_| CoreError::invalid("authentication body too large"))?;
        let email = if account_password {
            let access = parts
                .headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or_else(|| CoreError::Unauthorized("account session required".into()))?;
            let account = state.services.auth.authenticate_account(access).await?;
            state
                .repo
                .account_by_id(&account.user_id)
                .await?
                .ok_or_else(|| CoreError::Unauthorized("account no longer exists".into()))?
                .email
        } else if oauth {
            url::form_urlencoded::parse(&bytes)
                .find(|(key, _)| key == "email")
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default()
        } else {
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::invalid("invalid authentication request"))?;
            body.get("email").and_then(|v| v.as_str()).unwrap_or("account-password-change").to_owned()
        };
        let email = memoswish_auth::service::normalized_email(&email)?;
        state.auth_admission.account(&email).await?;
        let req = Request::from_parts(parts, Body::from(bytes));
        Ok::<_, CoreError>(memoswish_auth::password::with_source_permit(permit, next.run(req)).await)
    }
    .await;
    let mut response = match result {
        Ok(response) => response,
        Err(error) if oauth => {
            let mut response = (
                axum::http::StatusCode::from_u16(error.http_status()).expect("HTTP error"),
                axum::Json(
                    serde_json::json!({"error":"temporarily_unavailable","error_description":error.public_message()}),
                ),
            )
                .into_response();
            crate::admin::secure_headers(&mut response, false);
            response
        }
        Err(error) => ApiErr(error).into_response(),
    };
    if password_lifecycle {
        response
            .headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    }
    if response.status() == axum::http::StatusCode::TOO_MANY_REQUESTS {
        // 最慢账户维度每十秒恢复一次额度；这是保守的重试提示。
        response.headers_mut().insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from_static("10"));
    }
    response
}

// oneshot 测试显式提供传输元数据；生产路由仍在缺少元数据时关闭准入。
#[cfg(test)]
pub(crate) fn test_router(state: AppState) -> axum::Router {
    crate::api::router(state).layer(axum::Extension(ConnectInfo("127.0.0.1:12345".parse::<SocketAddr>().unwrap())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    #[test]
    fn proxy_boundary_and_configuration_are_explicit() {
        let mut config = crate::config::Config::default();
        config.password_work.workers = 1;
        assert!(config.validate().is_err());
        for email in ["x".repeat(255), "x".repeat(1025)] {
            assert!(memoswish_auth::service::normalized_email(&email).is_err());
        }
        assert!(memoswish_auth::service::normalized_email(&"x".repeat(254)).is_ok());
        let peer = "127.0.0.1:1234".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "192.0.2.1".parse().unwrap());
        headers.insert("forwarded", "for=198.51.100.1".parse().unwrap());
        let socket = ProxyTrust::default();
        assert_eq!(socket.source(Some(peer), &headers).unwrap(), "127.0.0.1");
        assert_eq!(socket.source(None, &headers).unwrap_err().http_status(), 503);
        let proxy = ProxyTrust {
            trusted_peers: vec!["127.0.0.1".parse().unwrap()],
            normalized_header: Some("x-real-ip".into()),
        };
        let deployed = include_str!("../../../../deploy/single-instance/Caddyfile");
        assert!(deployed.lines().any(|line| line.trim() == "header_up -X-Learntok-Client-IP"));
        let legacy = ProxyTrust { normalized_header: Some("x-learntok-client-ip".into()), ..proxy.clone() };
        legacy.validate().unwrap();
        headers.insert("x-learntok-client-ip", "192.0.2.1".parse().unwrap());
        assert_eq!(legacy.source(Some(peer), &headers).unwrap(), "192.0.2.1");
        assert_eq!(legacy.source(Some("192.0.2.10:1234".parse().unwrap()), &headers).unwrap(), "192.0.2.10");
        proxy.validate().unwrap();
        assert_eq!(proxy.source(Some(peer), &headers).unwrap(), "192.0.2.1");
        assert_eq!(proxy.source(Some("192.0.2.10:1234".parse().unwrap()), &headers).unwrap(), "192.0.2.10");
        for value in ["192.0.2.1, 192.0.2.2", "garbage", "", "192.0.2.1:80"] {
            headers.insert("x-real-ip", value.parse().unwrap());
            assert!(proxy.source(Some(peer), &headers).is_err());
        }
        headers.remove("x-real-ip");
        assert!(proxy.source(Some(peer), &headers).is_err());
        headers.append("x-real-ip", "192.0.2.1".parse().unwrap());
        headers.append("x-real-ip", "192.0.2.1".parse().unwrap());
        assert!(proxy.source(Some(peer), &headers).is_err());
        assert_eq!(socket.source(Some("[::ffff:192.0.2.1]:80".parse().unwrap()), &headers).unwrap(), "192.0.2.1");
        assert_eq!(
            socket.source(Some("[2001:db8::1]:80".parse().unwrap()), &headers).unwrap(),
            socket.source(Some("[2001:db8::ffff]:90".parse().unwrap()), &headers).unwrap()
        );
        for invalid in [
            ProxyTrust { trusted_peers: vec![], ..proxy.clone() },
            ProxyTrust { normalized_header: None, ..proxy.clone() },
            ProxyTrust { normalized_header: Some("x-forwarded-for".into()), ..proxy.clone() },
            ProxyTrust { trusted_peers: vec!["127.0.0.1".parse().unwrap(); 33], ..proxy },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[tokio::test]
    async fn bounded_dimensions_and_single_source_fairness() {
        let cfg = crate::admission::AdmissionConfig::default();
        let admission = AuthAdmission::build(&cfg).unwrap();
        let owned = admission.source("attacker").await.unwrap();
        assert_eq!(admission.source("attacker").await.unwrap_err().http_status(), 429);
        // 不同槽位的正常来源仍可进入，攻击者不能占有第二个 worker 或全部队列。
        let other = (0..100).map(|i| i.to_string()).find(|key| slot(key) != slot("attacker")).unwrap();
        assert!(admission.source(&other).await.is_ok());
        drop(owned);
        for _ in 0..19 {
            drop(admission.source("attacker").await.unwrap());
        }
        assert_eq!(admission.source("attacker").await.unwrap_err().http_status(), 429);
        for _ in 0..10 {
            admission.account("target@example.com").await.unwrap();
        }
        assert_eq!(admission.account("target@example.com").await.unwrap_err().http_status(), 429);
        assert_eq!(
            slot("target@example.com"),
            slot(&memoswish_auth::service::normalized_email(" TARGET@EXAMPLE.COM ").unwrap())
        );
        struct Keys(std::sync::Mutex<std::collections::HashSet<String>>);
        #[async_trait::async_trait]
        impl RateLimiter for Keys {
            async fn check(&self, key: &str, _: f64) -> CoreResult<()> {
                self.0.lock().unwrap().insert(key.to_owned());
                Ok(())
            }
        }
        let sources = Arc::new(Keys(Default::default()));
        let accounts = Arc::new(Keys(Default::default()));
        let mut churn = AuthAdmission::build(&cfg).unwrap();
        churn.sources = sources.clone();
        churn.accounts = accounts.clone();
        for i in 0..10000 {
            drop(churn.source(&format!("source-{i}")).await.unwrap());
            churn.account(&format!("rotated-{i}@example.com")).await.unwrap();
        }
        assert!(sources.0.lock().unwrap().len() <= SLOTS);
        assert!(accounts.0.lock().unwrap().len() <= SLOTS);
        let mut cfg = cfg;
        cfg.max_keys = SLOTS - 1;
        assert!(AuthAdmission::build(&cfg).is_err());
        cfg.max_keys = SLOTS;
        cfg.auth_failure = memoswish_core::rate_limit::FailureMode::Open;
        assert!(AuthAdmission::build(&cfg).is_err());
    }

    #[tokio::test]
    async fn source_ownership_precedes_waiting_for_shared_backend() {
        struct Paused {
            entered: tokio::sync::Notify,
            release: tokio::sync::Notify,
            calls: std::sync::atomic::AtomicUsize,
        }
        #[async_trait::async_trait]
        impl RateLimiter for Paused {
            async fn check(&self, _: &str, _: f64) -> CoreResult<()> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            }
        }
        let backend =
            Arc::new(Paused { entered: Default::default(), release: Default::default(), calls: Default::default() });
        let mut admission = AuthAdmission::build(&crate::admission::AdmissionConfig::default()).unwrap();
        admission.sources = backend.clone();
        let admission = Arc::new(admission);
        let request = {
            let admission = admission.clone();
            tokio::spawn(async move { admission.source("attacker").await })
        };
        backend.entered.notified().await;
        assert_eq!(admission.source("attacker").await.unwrap_err().http_status(), 429);
        assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(admission.active[slot("attacker")].available_permits(), 0);
        backend.release.notify_one();
        while admission.active[slot("attacker")].available_permits() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    async fn state() -> (AppState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("p38-{}", memoswish_core::ids::new_id()));
        let config = crate::config::Config {
            data_dir: dir.clone(),
            mode: memoswish_protocol::DeploymentMode::MultiTenant,
            registration_open: true,
            seed_demo: false,
            ..Default::default()
        };
        (AppState::build(config).await.unwrap(), dir)
    }
    fn login(path: &str, email: &str, password: &str) -> HttpRequest<Body> {
        HttpRequest::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"email":email,"password":password}).to_string()))
            .unwrap()
    }
    #[tokio::test]
    async fn every_password_route_has_admission_and_enumeration_resistance() {
        let (state, dir) = state().await;
        state
            .services
            .auth
            .register(&memoswish_protocol::RegisterRequest {
                email: "known@example.com".into(),
                password: "password123".into(),
                display_name: "Example".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        for path in ["/v1/auth/login", "/v1/auth/account-sessions", "/v1/auth/sessions"] {
            let app = test_router(state.clone());
            let known = app.clone().oneshot(login(path, "known@example.com", "incorrect")).await.unwrap();
            let unknown = app.clone().oneshot(login(path, "missing@example.com", "incorrect")).await.unwrap();
            assert_eq!(known.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(known.status(), unknown.status());
            assert_eq!(
                known.into_body().collect().await.unwrap().to_bytes(),
                unknown.into_body().collect().await.unwrap().to_bytes()
            );
            assert_eq!(
                app.oneshot(login(path, "missing@example.com", &"x".repeat(1025))).await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
        }
        for path in [
            "/v1/auth/register",
            "/v1/auth/login",
            "/v1/auth/account-sessions",
            "/v1/auth/sessions",
            "/v1/auth/sessions/register",
        ] {
            let response = crate::api::router(state.clone())
                .oneshot(login(path, "missing@example.com", "password123"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
            assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        }
        for _ in 0..10 {
            state.auth_admission.account("blocked@example.com").await.unwrap();
        }
        let response = test_router(state.clone())
            .oneshot(login("/v1/auth/login", "blocked@example.com", "password123"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "10");
        let response = test_router(state.clone())
            .oneshot(login("/v1/auth/login", &"x".repeat(1025), "password123"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let request = HttpRequest::post("/v1/auth/login").body(Body::from("x".repeat(16 * 1024 + 1))).unwrap();
        assert_eq!(test_router(state.clone()).oneshot(request).await.unwrap().status(), StatusCode::BAD_REQUEST);
        crate::runtime::cleanup_test_app(dir, &[&state]).await;
    }

    #[tokio::test]
    async fn admin_headers_cover_success_errors_assets_and_methods() {
        let (state, dir) = state().await;
        for (method, path, status) in [
            ("GET", "/admin", 200),
            ("GET", "/admin/script.js", 200),
            ("GET", "/admin/style.css", 200),
            ("GET", "/admin/missing", 404),
            ("GET", "/admin/", 404),
            ("POST", "/admin", 405),
            ("POST", "/admin/missing", 405),
        ] {
            let response = test_router(state.clone())
                .oneshot(HttpRequest::builder().method(method).uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
            let headers = response.headers();
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
            assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
            let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
            assert!(csp.contains("connect-src 'self'"));
            assert!(!csp.contains("unsafe-"));
        }
        let html = include_str!("admin.html");
        for forbidden in ["onclick=", "style=", "<style>", "<script>"] {
            assert!(!html.contains(forbidden));
        }
        let js = include_str!("admin.js");
        for forbidden in ["localStorage", "sessionStorage", "document.cookie", "innerHTML", "eval("] {
            assert!(!js.contains(forbidden));
        }
        assert!(html.contains("autocomplete=\"off\""));
        assert!(js.contains("pagehide"));
        crate::runtime::cleanup_test_app(dir, &[&state]).await;
    }

    #[tokio::test]
    async fn saturated_auth_source_does_not_change_readiness() {
        let (state, dir) = state().await;
        let held = state.auth_admission.source("127.0.0.1").await.unwrap();
        let response = test_router(state.clone())
            .oneshot(login("/v1/auth/login", "missing@example.com", "password123"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response =
            state.health.router().oneshot(HttpRequest::get("/readyz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(held);
        crate::runtime::drain_background(&state).await;
        crate::runtime::cleanup_test_app(dir, &[&state]).await;
    }
}

#[cfg(all(test, feature = "redis"))]
mod redis_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "integration: requires dedicated Redis"]
    async fn password_dimensions_share_quotas_across_replicas() {
        let endpoint = crate::test_environment::var("MEMOSWISH_TEST_REDIS_URL").expect("dedicated Redis URL required");
        let url = url::Url::parse(&endpoint).unwrap();
        assert_eq!(url.scheme(), "redis");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!((6380..=6399).contains(&url.port().expect("explicit throwaway port required")));
        let config = crate::admission::AdmissionConfig {
            backend: "redis".into(),
            redis_url: Some(endpoint),
            namespace: format!("p38-{}", memoswish_core::ids::new_id()),
            ..Default::default()
        };
        let first = AuthAdmission::build(&config).unwrap();
        let second = AuthAdmission::build(&config).unwrap();
        for _ in 0..5 {
            first.account("normalized@example.com").await.unwrap();
            second.account("normalized@example.com").await.unwrap();
        }
        assert_eq!(first.account("normalized@example.com").await.unwrap_err().http_status(), 429);
        assert_eq!(second.account("normalized@example.com").await.unwrap_err().http_status(), 429);
        for _ in 0..10 {
            drop(first.source("192.0.2.1").await.unwrap());
            drop(second.source("192.0.2.1").await.unwrap());
        }
        assert_eq!(second.source("192.0.2.1").await.unwrap_err().http_status(), 429);
    }
}
