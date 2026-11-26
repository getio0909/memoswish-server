//! 各路由类别独立组装准入策略；Redis 只存可丢弃的流量状态。

use std::sync::Arc;

use memoswish_core::rate_limit::{AdmissionQuota, FailureMode, PolicyLimiter, RateLimiter};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdmissionConfig {
    /// `memory` 为默认单实例实现；`redis` 需要同名编译特性。
    pub backend: String,
    /// Redis 连接 URL，可能包含凭据，配置输出始终脱敏。
    pub redis_url: Option<String>,
    /// 同一部署的副本必须使用相同前缀，不同部署必须隔离。
    pub namespace: String,
    /// 每次准入总期限，含建连、脚本与安全重试。
    pub timeout_ms: u64,
    /// 每个本地路由类别的键容量上限。
    pub max_keys: usize,
    pub work_failure: FailureMode,
    pub auth_failure: FailureMode,
    pub oauth_failure: FailureMode,
    pub oidc_failure: FailureMode,
}

impl std::fmt::Debug for AdmissionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionConfig")
            .field("backend", &self.backend)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "***"))
            .finish_non_exhaustive()
    }
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            backend: "memory".into(),
            redis_url: None,
            namespace: "learntok".into(),
            timeout_ms: 500,
            max_keys: 10_000,
            work_failure: FailureMode::Closed,
            auth_failure: FailureMode::Closed,
            oauth_failure: FailureMode::Closed,
            oidc_failure: FailureMode::Closed,
        }
    }
}

pub fn build(
    config: &AdmissionConfig,
    class: &str,
    burst: u32,
    refill: f64,
    failure: FailureMode,
) -> anyhow::Result<Arc<dyn RateLimiter>> {
    build_observed(config, class, burst, refill, failure, memoswish_core::observability::noop())
}

pub fn build_observed(
    config: &AdmissionConfig,
    class: &str,
    burst: u32,
    refill: f64,
    failure: FailureMode,
    observer: Arc<dyn memoswish_core::observability::Observer>,
) -> anyhow::Result<Arc<dyn RateLimiter>> {
    let quota = AdmissionQuota::new(burst, refill)?;
    anyhow::ensure!(
        config.max_keys > 0
            && (1..=30_000).contains(&config.timeout_ms)
            && !config.namespace.is_empty()
            && config.namespace.len() <= 128,
        "invalid admission configuration"
    );
    let backend: Arc<dyn RateLimiter> = match config.backend.as_str() {
        "memory" => Arc::new(memoswish_auth::RateLimiter::bounded(burst, refill, config.max_keys)?),
        "redis" => {
            let url =
                config.redis_url.as_deref().ok_or_else(|| anyhow::anyhow!("Redis admission requires redis_url"))?;
            #[cfg(feature = "redis")]
            {
                Arc::new(memoswish_storage::redis_limiter::RedisRateLimiter::new(
                    url,
                    config.namespace.clone(),
                    quota,
                    std::time::Duration::from_millis(config.timeout_ms),
                )?)
            }
            #[cfg(not(feature = "redis"))]
            {
                let _ = url;
                anyhow::bail!("Redis admission requires the redis feature");
            }
        }
        _ => anyhow::bail!("unknown admission backend"),
    };
    let class_label = match class {
        "password-source" => Some(AdmissionClass::PasswordSource),
        "password-account" => Some(AdmissionClass::PasswordAccount),
        "work" => Some(AdmissionClass::Work),
        "auth" => Some(AdmissionClass::Auth),
        "oauth" => Some(AdmissionClass::Oauth),
        "oidc" => Some(AdmissionClass::Oidc),
        _ => None,
    };
    let backend: Arc<dyn RateLimiter> = Arc::new(ObservedBackend { backend, observer, class: class_label, failure });
    Ok(Arc::new(PolicyLimiter { backend, namespace: class.into(), quota, failure }))
}

use memoswish_core::observability::{AdmissionClass, AdmissionOutcome, Observer};
struct ObservedBackend {
    backend: Arc<dyn RateLimiter>,
    observer: Arc<dyn Observer>,
    class: Option<AdmissionClass>,
    failure: FailureMode,
}
#[async_trait::async_trait]
impl RateLimiter for ObservedBackend {
    async fn check(&self, key: &str, cost: f64) -> memoswish_core::CoreResult<()> {
        let mut attempt =
            self.class.map(|class| memoswish_core::observability::AdmissionAttempt::new(self.observer.clone(), class));
        let result = self.backend.check(key, cost).await;
        if self.class.is_some() {
            use memoswish_core::CoreError;
            let outcome = match &result {
                Ok(_) => AdmissionOutcome::Accepted,
                Err(CoreError::QuotaExceeded(_)) => AdmissionOutcome::Rejected,
                Err(CoreError::Unavailable(_)) if matches!(self.failure, FailureMode::Open) => {
                    AdmissionOutcome::FailOpen
                }
                Err(CoreError::Unavailable(_)) => AdmissionOutcome::Unavailable,
                _ => AdmissionOutcome::Invalid,
            };
            if let Some(attempt) = attempt.as_mut() {
                attempt.finish(outcome);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_configuration_and_credentials_are_safe() {
        let mut cfg = AdmissionConfig {
            backend: "unknown".into(),
            redis_url: Some("redis://private:secret@host/?token=hidden".into()),
            ..Default::default()
        };
        assert!(build(&cfg, "auth", 60, 1.0, FailureMode::Closed).is_err());
        assert!(!format!("{cfg:?}").contains("secret"));
        cfg.backend = "memory".into();
        assert!(build(&cfg, "work", 0, 1.0, FailureMode::Closed).is_err());
        #[cfg(feature = "redis")]
        {
            cfg.backend = "redis".into();
            cfg.redis_url = Some("synthetic-private-secret".into());
            let error = build(&cfg, "auth", 60, 1.0, FailureMode::Open).err().unwrap();
            for text in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
                assert!(!text.contains("synthetic-private-secret"));
                assert!(text.contains("invalid Redis URL"));
            }
        }
        cfg.max_keys = 0;
        assert!(build(&cfg, "auth", 60, 1.0, FailureMode::Closed).is_err());
    }

    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn startup_failure_uses_each_explicit_route_policy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = AdmissionConfig {
            backend: "redis".into(),
            redis_url: Some(format!("redis://{}", listener.local_addr().unwrap())),
            timeout_ms: 30,
            ..Default::default()
        };
        for class in ["auth", "oauth", "oidc", "work"] {
            let closed = build(&cfg, class, 60, 1.0, FailureMode::Closed).unwrap();
            let open = build(&cfg, class, 60, 1.0, FailureMode::Open).unwrap();
            assert_eq!(closed.check("a", 1.0).await.unwrap_err().http_status(), 503);
            open.check("a", 1.0).await.unwrap();
            assert_eq!(open.check("a", f64::NAN).await.unwrap_err().http_status(), 400);
        }
    }
}
