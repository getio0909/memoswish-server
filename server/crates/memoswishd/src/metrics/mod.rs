//! 每个 daemon 独立注册；固定桶、有限标签及有界编码，不建立采样循环。

use axum::{
    extract::MatchedPath,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use memoswish_core::observability::*;
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use std::{io::Write, sync::Arc, time::Instant};

mod routes;
#[cfg(test)]
mod tests;
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const MAX_BYTES: usize = 4 * 1024 * 1024;
const BUCKETS: &[f64] = &[0.005, 0.025, 0.1, 0.25, 1.0, 5.0, 15.0, 60.0];

pub(crate) fn route<B>(request: &Request<B>) -> &'static str {
    request.extensions().get::<MatchedPath>().map_or("unmatched", |p| routes::normalize(p.as_str()))
}
fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}
pub(crate) struct Metrics {
    registry: Registry,
    pub http_requests: IntCounter,
    pub engines: IntGauge,
    responses: IntCounterVec,
    duration: HistogramVec,
    cancellations: IntCounterVec,
    operations: HistogramVec,
    reviews: IntCounterVec,
    feed_retries: IntCounterVec,
    dispositions: IntCounterVec,
    admissions: IntCounterVec,
    used: IntGaugeVec,
    capacity: IntGaugeVec,
    pool: IntGaugeVec,
    pending: IntGaugeVec,
    unknown: IntGaugeVec,
    future: IntGaugeVec,
    age: GaugeVec,
    cleanup_lag: GaugeVec,
    maintenance_states: IntGaugeVec,
    maintenance_pages: IntCounterVec,
    sample_success: IntGauge,
    sample_time: prometheus::Gauge,
    sample_errors: IntCounter,
    pub(crate) sampling: tokio::sync::Semaphore,
    encoding: tokio::sync::Semaphore,
}
impl Metrics {
    pub(crate) fn new(mode: memoswish_protocol::DeploymentMode) -> prometheus::Result<Arc<Self>> {
        let registry = Registry::new();
        macro_rules! register {
            ($v:expr) => {{
                let v = $v?;
                registry.register(Box::new(v.clone()))?;
                v
            }};
        }
        let build = register!(IntGaugeVec::new(
            Opts::new("learntok_build_info", "Build and deployment metadata for memoswishd."),
            &["version", "mode"]
        ));
        build
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                match mode {
                    memoswish_protocol::DeploymentMode::SingleUser => "single_user",
                    memoswish_protocol::DeploymentMode::MultiTenant => "multi_tenant",
                },
            ])
            .set(1);
        Ok(Arc::new(Self {
            http_requests: register!(IntCounter::new(
                "learntok_http_requests_total",
                "Total number of HTTP requests handled."
            )),
            engines: register!(IntGauge::new(
                "learntok_tts_engines_registered",
                "Number of registered TTS synthesis engines."
            )),
            responses: register!(IntCounterVec::new(
                Opts::new("memoswish_http_responses_total", "Responses with headers ready."),
                &["route", "status_class"]
            )),
            duration: register!(HistogramVec::new(
                HistogramOpts::new(
                    "memoswish_http_request_duration_seconds",
                    "Time until response headers, excluding body lifetime."
                )
                .buckets(BUCKETS.to_vec()),
                &["route", "status_class"]
            )),
            cancellations: register!(IntCounterVec::new(
                Opts::new("memoswish_http_cancellations_total", "Requests cancelled before response headers."),
                &["route"]
            )),
            operations: register!(HistogramVec::new(
                HistogramOpts::new(
                    "memoswish_operation_duration_seconds",
                    "Real operation owner duration and terminal outcome."
                )
                .buckets(BUCKETS.to_vec()),
                &["operation", "outcome"]
            )),
            feed_retries: register!(IntCounterVec::new(
                Opts::new("memoswish_feed_retries_total", "Failed feed issuance attempts by bounded internal cause."),
                &["cause"]
            )),
            reviews: register!(IntCounterVec::new(
                Opts::new("memoswish_reviews_total", "Final per-event acceptance results."),
                &["outcome"]
            )),
            dispositions: register!(IntCounterVec::new(
                Opts::new(
                    "memoswish_review_dispositions_total",
                    "Disposition of newly committed accepted events; late is a subset."
                ),
                &["disposition"]
            )),
            admissions: register!(IntCounterVec::new(
                Opts::new("memoswish_admissions_total", "Admission decisions, including backend fail-open."),
                &["class", "outcome"]
            )),
            used: register!(IntGaugeVec::new(
                Opts::new(
                    "memoswish_admission_in_flight",
                    "Locally owned slots including queued work where indicated."
                ),
                &["class"]
            )),
            capacity: register!(IntGaugeVec::new(
                Opts::new("memoswish_admission_capacity", "Configured local slot capacity."),
                &["class"]
            )),
            pool: register!(IntGaugeVec::new(
                Opts::new(
                    "memoswish_db_pool_connections",
                    "SQLx pool snapshot; used is an estimate, not wait queue length."
                ),
                &["state"]
            )),
            pending: register!(IntGaugeVec::new(
                Opts::new("memoswish_pending_work", "Shared SQL pending responsibility, including exhausted work."),
                &["kind"]
            )),
            unknown: register!(IntGaugeVec::new(
                Opts::new("memoswish_pending_timestamp_unknown", "Pending rows with historical unknown start time."),
                &["kind"]
            )),
            future: register!(IntGaugeVec::new(
                Opts::new("memoswish_pending_timestamp_future", "Pending rows with anomalous future start time."),
                &["kind"]
            )),
            age: register!(GaugeVec::new(
                Opts::new(
                    "memoswish_oldest_known_pending_age_seconds",
                    "Age from database time; NaN when no known pending start."
                ),
                &["kind"]
            )),
            cleanup_lag: register!(GaugeVec::new(
                Opts::new(
                    "memoswish_cleanup_lag_seconds",
                    "Age of unresolved cleanup responsibility; NaN without known pending start."
                ),
                &["kind"]
            )),
            maintenance_states: register!(IntGaugeVec::new(
                Opts::new(
                    "memoswish_maintenance_tasks",
                    "Enabled persistent maintenance tasks by bounded kind and state."
                ),
                &["task_kind", "task_state"]
            )),
            maintenance_pages: register!(IntCounterVec::new(
                Opts::new(
                    "memoswish_maintenance_pages_total",
                    "Observed scheduling page results; not business completion."
                ),
                &["task_kind", "outcome"]
            )),
            sample_success: register!(IntGauge::new(
                "memoswish_operational_sample_success",
                "Whether the last attempted SQL sample succeeded."
            )),
            sample_time: register!(prometheus::Gauge::new(
                "memoswish_operational_sample_timestamp_seconds",
                "Database time of last successful sample, zero before first success."
            )),
            sample_errors: register!(IntCounter::new(
                "memoswish_operational_sample_errors_total",
                "Failed or cancelled SQL samples; last good gauges retained."
            )),
            registry,
            sampling: tokio::sync::Semaphore::new(1),
            encoding: tokio::sync::Semaphore::new(1),
        }))
    }
    pub(crate) fn http(self: &Arc<Self>, route: &'static str) -> HttpGuard {
        HttpGuard { metrics: self.clone(), route, started: Instant::now(), complete: false }
    }
    pub(crate) fn set_pool(&self, pool: PoolSnapshot) {
        for (state, value) in [
            ("size", pool.size as i64),
            ("idle", pool.idle as i64),
            ("capacity", pool.capacity as i64),
            ("used_estimate", (pool.size as usize).saturating_sub(pool.idle) as i64),
        ] {
            self.pool.with_label_values(&[state]).set(value);
        }
    }
    pub(crate) fn sampled(&self, snapshot: OperationalSnapshot) {
        for kind in WorkKind::ALL {
            let row = snapshot.pending.iter().find(|row| row.kind == *kind);
            let labels = &[kind.label()];
            self.pending.with_label_values(labels).set(row.map_or(0, |r| r.count));
            self.unknown.with_label_values(labels).set(row.map_or(0, |r| r.unknown));
            self.future.with_label_values(labels).set(row.map_or(0, |r| r.future));
            let age = row
                .and_then(|r| r.oldest_ms)
                .map_or(f64::NAN, |ms| snapshot.observed_at_ms.saturating_sub(ms).max(0) as f64 / 1000.0);
            self.age.with_label_values(labels).set(age);
            if matches!(
                kind,
                WorkKind::Erasure
                    | WorkKind::Orphan
                    | WorkKind::ManagedWrite
                    | WorkKind::ExpiredOauth
                    | WorkKind::ExpiredOidc
                    | WorkKind::ExpiredPassword
                    | WorkKind::Lifecycle
                    | WorkKind::Maintenance
            ) {
                self.cleanup_lag.with_label_values(labels).set(age);
            }
        }
        for kind in memoswish_core::maintenance::TaskKind::ALL {
            for state in TaskState::ALL {
                let count =
                    snapshot.maintenance.iter().find(|r| r.kind == *kind && r.state == *state).map_or(0, |r| r.count);
                self.maintenance_states.with_label_values(&[kind.as_str(), state.label()]).set(count);
            }
        }
        self.sample_time.set(snapshot.observed_at_ms as f64 / 1000.0);
        self.sample_success.set(1);
    }
    pub(crate) fn sample_failed(&self) {
        self.sample_success.set(0);
        self.sample_errors.inc();
    }
    fn encode(&self, legacy: bool) -> prometheus::Result<Vec<u8>> {
        let families = self
            .registry
            .gather()
            .into_iter()
            .filter(|family| {
                !legacy
                    || matches!(
                        family.name(),
                        "learntok_build_info" | "learntok_http_requests_total" | "learntok_tts_engines_registered"
                    )
            })
            .collect::<Vec<_>>();
        let mut writer = BoundedWriter(Vec::new());
        TextEncoder::new().encode(&families, &mut writer)?;
        Ok(writer.0)
    }
    pub(crate) fn response(&self, legacy: bool) -> Response {
        let Ok(_permit) = self.encoding.try_acquire() else {
            return (StatusCode::SERVICE_UNAVAILABLE, "metrics busy").into_response();
        };
        match self.encode(legacy) {
            Ok(body) => ([(axum::http::header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response(),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "metrics encoding unavailable").into_response(),
        }
    }
}
struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(std::io::Error::other("metrics size limit exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) struct HttpGuard {
    metrics: Arc<Metrics>,
    route: &'static str,
    started: Instant,
    complete: bool,
}
impl HttpGuard {
    pub(crate) fn finish(&mut self, status: StatusCode) {
        let labels = &[self.route, status_class(status)];
        self.metrics.responses.with_label_values(labels).inc();
        self.metrics.duration.with_label_values(labels).observe(self.started.elapsed().as_secs_f64());
        self.complete = true;
    }
}
impl Drop for HttpGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.metrics.cancellations.with_label_values(&[self.route]).inc();
        }
    }
}
struct Guard {
    metric: HistogramVec,
    operation: Operation,
    started: Instant,
    complete: bool,
}
impl ObservationGuard for Guard {
    fn finish(&mut self, outcome: Outcome) {
        if !self.complete {
            self.metric
                .with_label_values(&[self.operation.label(), outcome.label()])
                .observe(self.started.elapsed().as_secs_f64());
            self.complete = true;
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}
impl Observer for Metrics {
    fn feed_retry(&self, cause: FeedRetryCause) {
        self.feed_retries.with_label_values(&[cause.label()]).inc();
    }
    fn maintenance(&self, kind: memoswish_core::maintenance::TaskKind, success: bool) {
        self.maintenance_pages.with_label_values(&[kind.as_str(), if success { "returned" } else { "error" }]).inc();
    }
    fn start(&self, operation: Operation) -> Box<dyn ObservationGuard> {
        Box::new(Guard { metric: self.operations.clone(), operation, started: Instant::now(), complete: false })
    }
    fn review(&self, outcome: ReviewOutcome) {
        self.reviews.with_label_values(&[outcome.label()]).inc();
    }
    fn disposition(&self, d: memoswish_core::repo::LearningDisposition) {
        use memoswish_core::repo::LearningDisposition::*;
        self.dispositions
            .with_label_values(&[match d {
                Scheduled => "scheduled",
                LateNotScheduled => "late_not_scheduled",
                FutureNotScheduled => "future_not_scheduled",
                NotRated => "not_rated",
            }])
            .inc();
    }
    fn admission(&self, class: AdmissionClass, outcome: AdmissionOutcome) {
        self.admissions.with_label_values(&[class.label(), outcome.label()]).inc();
    }
    fn slot(&self, class: AdmissionClass, delta: i64) {
        self.used.with_label_values(&[class.label()]).add(delta);
    }
    fn capacity(&self, class: AdmissionClass, used: usize, capacity: usize) {
        self.used.with_label_values(&[class.label()]).set(used as i64);
        self.capacity.with_label_values(&[class.label()]).set(capacity as i64);
    }
}

/// 现有生命周期与 S26c 调度在其 pass 中调用；scrape 只编码缓存，绝不联系 SQL。
pub(crate) async fn sample(st: &crate::app::AppState) {
    let Ok(_permit) = st.metrics.sampling.try_acquire() else {
        return;
    };
    st.metrics.set_pool(st.repo.pool_snapshot());
    struct Sample<'a>(&'a Metrics, bool);
    impl Drop for Sample<'_> {
        fn drop(&mut self) {
            if !self.1 {
                self.0.sample_failed();
            }
        }
    }
    let mut sample = Sample(&st.metrics, false);
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(st.config.admission.timeout_ms),
        st.repo.operational_snapshot(),
    )
    .await;
    if let Ok(Ok(snapshot)) = result {
        st.metrics.sampled(snapshot);
        sample.1 = true;
    }
}
