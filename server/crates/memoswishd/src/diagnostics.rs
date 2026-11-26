//! 第一方接收与可选 GlitchTip 适配；不安装 panic/tracing 全局宿主钩子。
use crate::{
    api::{ApiResult, Auth},
    app::AppState,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::post,
};
use memoswish_core::{CoreError, CoreResult, Principal};
use memoswish_protocol::{DiagnosticReceipt, DiagnosticReport, PrivacyPolicy};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardingConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub public_key: String,
    pub purpose_version: String,
}
impl std::fmt::Debug for ForwardingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardingConfig").field("enabled", &self.enabled).finish_non_exhaustive()
    }
}
impl ForwardingConfig {
    pub fn recipient_version(&self) -> String {
        let identity = serde_json::to_vec(&(&self.endpoint, &self.public_key)).expect("string tuple serializes");
        format!("glitchtip-{}", memoswish_core::ids::sha256_hex(&identity))
    }
    pub fn validate(&self, policy: &PrivacyPolicy) -> CoreResult<()> {
        if !self.enabled {
            return Ok(());
        }
        let url = url::Url::parse(&self.endpoint)
            .map_err(|_| CoreError::invalid("invalid diagnostic forwarding endpoint"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with("/envelope/")
            || self.public_key.is_empty()
            || self.public_key.len() > 128
            || !self.public_key.bytes().all(|b| b.is_ascii_alphanumeric())
            || self.purpose_version != self.recipient_version()
            || policy.purpose_versions.get("diagnostics") != Some(&self.purpose_version)
        {
            return Err(CoreError::invalid(
                "diagnostic forwarding requires HTTPS envelope endpoint and current recipient purpose version",
            ));
        }
        Ok(())
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/diagnostics/reports", post(receive))
        .layer(DefaultBodyLimit::max(memoswish_core::diagnostics::MAX_REPORT_BYTES))
}
async fn receive(
    State(st): State<AppState>,
    Auth(p): Auth,
    body: Result<Json<DiagnosticReport>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<([(axum::http::HeaderName, &'static str); 1], Json<DiagnosticReceipt>)> {
    let Json(report) = body.map_err(|_| CoreError::invalid("invalid or oversized diagnostic report"))?;
    let receipt = st.services.report_forwardable_diagnostic(&p, &report).await?;
    forward(&st, &p, &report).await;
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(receipt)))
}

fn envelope(report: &DiagnosticReport, event_id: &str) -> CoreResult<String> {
    memoswish_core::diagnostics::validate(report)?;
    // 不转发第一方所有者、同意修订、原始异常或接收方策略标识。
    let event = serde_json::json!({"event_id":event_id,"platform":"other","level":"error",
        "release":report.build,"message":report.code,"tags":{"platform":report.platform,"category":report.category},
        "exception":{"values":[{"type":report.code,"stacktrace":{"frames":report.frames.iter().map(|f|serde_json::json!({"module":f,"function":"redacted","in_app":true})).collect::<Vec<_>>()}}]}}).to_string();
    Ok(format!(
        "{}\n{}\n{event}\n",
        serde_json::json!({"event_id":event_id}),
        serde_json::json!({"type":"event","length":event.len()})
    ))
}
pub(crate) async fn forward(st: &AppState, p: &Principal, report: &DiagnosticReport) {
    let config = &st.config.diagnostic_forwarding;
    if !config.enabled || config.validate(st.services.auth.privacy_policy()).is_err() {
        return;
    }
    let owned = st.clone();
    let principal = p.clone();
    let report = report.clone();
    // 请求取消只丢弃等待者；转发归已有任务跟踪器，沿共享关闭期限排空。
    if let Some(task) = spawn_forwarding(st, async move { forward_owned(&owned, &principal, &report).await }) {
        let _ = task.await;
    }
}

pub(crate) fn spawn_forwarding(
    st: &AppState,
    operation: impl std::future::Future<Output = ()> + Send + 'static,
) -> Option<tokio::task::JoinHandle<()>> {
    if !st.config.role.executes() || !st.config.diagnostic_forwarding.enabled {
        return None;
    }
    let lifecycle = st.health.lifecycle.clone();
    st.services
        .operations
        .spawn(async move {
            // 期限耗尽时取消网络等待，不让诊断任务在守护进程停止后继续外发。
            tokio::select! {
                biased;
                _ = async {
                    lifecycle.draining().await;
                    tokio::time::sleep_until(lifecycle.drain()).await;
                } => {},
                _ = operation => {},
            }
        })
        .ok()
}

async fn forward_owned(st: &AppState, p: &Principal, report: &DiagnosticReport) {
    let config = &st.config.diagnostic_forwarding;
    let scope = serde_json::to_vec(&(&p.tenant_id, &p.user_id, &report.report_id)).expect("string tuple serializes");
    let event_id = memoswish_core::ids::sha256_hex(&scope);
    let Ok(body) = envelope(report, &event_id[..32]) else {
        return;
    };
    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(5))
        .build()
    else {
        return;
    };
    // 事务提交标记是撤回排序的不可追回发送边界，不持 SQL 事务跨网络。
    if !matches!(st.services.auth.dispatch_diagnostic(p, report).await, Ok(true)) {
        return;
    }
    let _ = client
        .post(&config.endpoint)
        .header("X-Sentry-Auth", format!("Sentry sentry_version=7,sentry_key={}", config.public_key))
        .header("Content-Type", "application/x-sentry-envelope")
        .body(body)
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn forwarding_is_cancelled_at_the_existing_shutdown_deadline() {
        let dir = std::env::temp_dir().join(format!("s29b-deadline-{}", memoswish_core::ids::new_id()));
        let mut st = AppState::build(crate::Config { data_dir: dir.clone(), ..Default::default() }).await.unwrap();
        std::sync::Arc::make_mut(&mut st.config).diagnostic_forwarding.enabled = true;
        tokio::time::pause();
        let (held, dropped) = tokio::sync::oneshot::channel::<()>();
        let task = spawn_forwarding(&st, async move {
            let _held = held;
            std::future::pending::<()>().await;
        })
        .unwrap();
        let deadline = st.health.lifecycle.drain();
        tokio::time::advance(deadline - tokio::time::Instant::now()).await;
        task.await.unwrap();
        assert!(dropped.await.is_err(), "deadline must drop the pending forwarding future");
        assert_eq!(st.health.lifecycle.drain(), deadline);
        crate::runtime::drain_background(&st).await;
        assert_eq!(st.health.lifecycle.phase(), crate::lifecycle::Phase::Stopped);
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn forwarding_obeys_roles_cancellation_ownership_and_shared_drain() {
        use crate::deployment::Role;
        let dir = std::env::temp_dir().join(format!("s29b-drain-{}", memoswish_core::ids::new_id()));
        let mut st = AppState::build(crate::Config { data_dir: dir.clone(), ..Default::default() }).await.unwrap();
        assert!(spawn_forwarding(&st, async { panic!("disabled forwarding executed") }).is_none());
        std::sync::Arc::make_mut(&mut st.config).diagnostic_forwarding.enabled = true;
        for role in [Role::Api, Role::Maintenance, Role::Migrator] {
            std::sync::Arc::make_mut(&mut st.config).role = role;
            assert!(spawn_forwarding(&st, async { panic!("role without work executed forwarding") }).is_none());
        }
        for role in [Role::Worker, Role::AllInOne] {
            std::sync::Arc::make_mut(&mut st.config).role = role;
            spawn_forwarding(&st, async {}).unwrap().await.unwrap();
        }
        let (release, blocked) = tokio::sync::oneshot::channel::<()>();
        let (finished, completed) = tokio::sync::oneshot::channel();
        let task = spawn_forwarding(&st, async move {
            blocked.await.unwrap();
            finished.send(()).unwrap();
        })
        .unwrap();
        // 丢弃 HTTP 等待句柄不能取消已接受的转发。
        drop(task);
        let deadline = st.health.lifecycle.drain();
        {
            let drain = crate::runtime::drain_background(&st);
            tokio::pin!(drain);
            tokio::select! {
                biased;
                _ = &mut drain => panic!("drain returned before accepted forwarding completed"),
                _ = tokio::task::yield_now() => {},
            }
            assert_eq!(st.health.lifecycle.drain(), deadline);
            assert!(spawn_forwarding(&st, async { panic!("forwarding admitted after close") }).is_none());
            release.send(()).unwrap();
            drain.await;
            completed.await.unwrap();
            assert_eq!(st.health.lifecycle.phase(), crate::lifecycle::Phase::Stopped);
        }
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }

    #[test]
    fn forwarding_minimizes_and_fails_closed() {
        let report = memoswish_protocol::examples::sample_diagnostic_report();
        let body = envelope(&report, &report.report_id).unwrap();
        for excluded in ["privacy_revision", "purpose_version", "user_id", "tenant_id"] {
            assert!(!body.contains(excluded));
        }
        assert!(!ForwardingConfig::default().enabled);
        let mut config = ForwardingConfig {
            enabled: true,
            endpoint: "https://errors.example/api/1/envelope/".into(),
            public_key: "public123".into(),
            purpose_version: "diagnostics-v1".into(),
        };
        config.purpose_version = config.recipient_version();
        let mut policy = PrivacyPolicy::default();
        assert!(config.validate(&policy).is_err());
        policy.purpose_versions.insert("diagnostics".into(), config.purpose_version.clone());
        assert!(config.validate(&policy).is_ok());
        for endpoint in [
            "http://errors.example/api/1/envelope/",
            "https://secret@errors.example/api/1/envelope/",
            "https://errors.example/api/1/envelope/?secret=x",
        ] {
            config.endpoint = endpoint.into();
            assert!(config.validate(&policy).is_err());
            assert!(!format!("{config:?}").contains("secret"));
        }
    }
}
