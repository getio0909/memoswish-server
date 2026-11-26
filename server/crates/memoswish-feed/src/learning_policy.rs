//! 接受序列的时间处置与应用策略来源。

use chrono::{DateTime, Utc};
use memoswish_core::repo::{LearningApplication, LearningDisposition, SignalThresholds};
use memoswish_protocol::ImplicitFeedback;

use crate::{Fsrs, Outcome, SignalPolicy};

/// 先按原始瞬间排除未来，再按共同的毫秒精度比较，保留旧投影的更细精度屏障。
pub(crate) fn application(
    event: &ImplicitFeedback,
    received_at: DateTime<Utc>,
    last_review: Option<DateTime<Utc>>,
    outcome: Outcome,
    signals: &SignalPolicy,
    fsrs: &Fsrs,
) -> LearningApplication {
    let effective = DateTime::from_timestamp_millis(event.shown_at.timestamp_millis()).expect("valid UTC milliseconds");
    let disposition = if event.shown_at > received_at {
        LearningDisposition::FutureNotScheduled
    } else if outcome.rating.is_none() {
        LearningDisposition::NotRated
    } else if last_review.is_some_and(|last| effective < last) {
        LearningDisposition::LateNotScheduled
    } else {
        LearningDisposition::Scheduled
    };
    LearningApplication {
        disposition,
        effective_at: (disposition == LearningDisposition::Scheduled).then_some(effective),
        star: outcome.star,
        signal_version: "implicit-signals-v1".into(),
        signal_thresholds: SignalThresholds {
            fast_swipe_ms: signals.fast_swipe_ms,
            reinforce_loops: signals.reinforce_loops,
            slow_flip_ms: signals.slow_flip_ms,
            idle_ms: signals.idle_ms,
        },
        scheduler_algorithm: "FSRS-6".into(),
        scheduler_package_version: crate::fsrs::PACKAGE_VERSION.into(),
        scheduler_adapter_version: "learntok-fsrs-v2".into(),
        scheduler_parameters: fsrs.parameters().to_vec(),
        desired_retention: fsrs.desired_retention,
        chronology_version: "acceptance-sequence-ms-v1".into(),
        day_policy_version: "elapsed-utc-24h-floor-v1".into(),
        issued_delivery: None,
        attribution_source: "acceptance_time_configuration".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rating;
    use chrono::Duration;

    #[test]
    fn precise_chronology_and_legacy_precision_barrier() {
        let mut event = memoswish_protocol::examples::sample_feedback_batch().events[0].clone();
        let base: DateTime<Utc> = "2026-11-01T00:00:00.123Z".parse().unwrap();
        event.shown_at = base + Duration::nanoseconds(900_000);
        let now = base + Duration::days(1);
        let outcome = Outcome { rating: Some(Rating::Good), star: false };
        let make = |last| application(&event, now, last, outcome, &SignalPolicy::default(), &Fsrs::default());
        assert_eq!(make(Some(base)).effective_at, Some(base));
        assert_eq!(make(Some(base + Duration::nanoseconds(1))).disposition, LearningDisposition::LateNotScheduled);
        assert_eq!(make(None).effective_at, Some(base));
        assert_eq!(make(None).scheduler_parameters, fsrs::DEFAULT_PARAMETERS);
        assert_eq!(event.shown_at.timestamp_subsec_nanos(), 123_900_000);
    }

    #[test]
    fn elapsed_utc_days_across_dst_midnight_and_travel() {
        let fsrs = Fsrs::default();
        let memory = fsrs.review(None, 0.0, Rating::Good).unwrap().memory;
        for (a, b, days) in [
            ("2026-03-07T12:00:00-08:00", "2026-03-08T12:00:00-07:00", 0.0),
            ("2026-10-31T12:00:00-07:00", "2026-11-01T12:00:00-08:00", 1.0),
            ("2026-11-01T23:59:59Z", "2026-11-02T00:00:00Z", 0.0),
            ("2026-11-01T10:00:00+08:00", "2026-11-01T18:00:00-08:00", 1.0),
            ("2026-11-01T10:00:00+08:00", "2026-11-02T01:59:59.999Z", 0.0),
        ] {
            let a = a.parse::<DateTime<Utc>>().unwrap();
            let b = b.parse::<DateTime<Utc>>().unwrap();
            let elapsed = (b - a).num_milliseconds() as f64 / 86_400_000.0;
            assert_eq!(
                fsrs.review(Some(memory), elapsed, Rating::Good).unwrap(),
                fsrs.review(Some(memory), days, Rating::Good).unwrap()
            );
        }
    }
}
