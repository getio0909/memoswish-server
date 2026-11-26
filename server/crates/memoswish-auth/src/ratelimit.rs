//! governor 驱动的有界本地准入；仅回收空闲至少一个完整补充周期的键。

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use governor::{
    Quota,
    clock::{Clock, DefaultClock, Reference},
    state::{InMemoryState, NotKeyed},
};
use memoswish_core::{
    CoreError, CoreResult,
    ids::sha256_hex,
    rate_limit::{AdmissionQuota, RateLimiter as Admission},
};

type Governor<C> =
    governor::RateLimiter<NotKeyed, InMemoryState, C, governor::middleware::NoOpMiddleware<<C as Clock>::Instant>>;
struct Bucket<C: Clock> {
    limiter: Governor<C>,
    last: C::Instant,
}

pub struct RateLimiter<C: Clock = DefaultClock> {
    quota: AdmissionQuota,
    max_keys: usize,
    clock: C,
    buckets: Mutex<HashMap<String, Bucket<C>>>,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill: f64) -> Self {
        Self::bounded(capacity, refill, 10_000).expect("valid local admission quota")
    }

    pub fn bounded(capacity: u32, refill: f64, max_keys: usize) -> CoreResult<Self> {
        Self::with_clock(AdmissionQuota::new(capacity, refill)?, max_keys, DefaultClock::default())
    }
}

impl<C: Clock + Clone> RateLimiter<C> {
    pub fn with_clock(quota: AdmissionQuota, max_keys: usize, clock: C) -> CoreResult<Self> {
        if max_keys == 0 {
            return Err(CoreError::invalid("admission max_keys must be positive"));
        }
        Ok(Self { quota, max_keys, clock, buckets: Mutex::new(HashMap::new()) })
    }

    fn check_local(&self, key: &str, cost: f64) -> CoreResult<()> {
        let cells = self.quota.cost_cells(cost)?;
        let key = sha256_hex(key.as_bytes());
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.clock.now();
        if !map.contains_key(&key) {
            // 仅在新键抵达时扫描；已耗尽桶在自然完全恢复前始终占据一个位置。
            map.retain(|_, b| std::time::Duration::from(now.duration_since(b.last)) < self.quota.ttl());
            if map.len() >= self.max_keys {
                return Err(CoreError::QuotaExceeded("rate limiter key capacity reached".into()));
            }
        }
        let bucket = map.entry(key).or_insert_with(|| Bucket {
            limiter: Governor::direct_with_clock(
                Quota::with_period(self.quota.period()).expect("positive period").allow_burst(self.quota.burst()),
                self.clock.clone(),
            ),
            last: now,
        });
        let decision = bucket.limiter.check_n(cells);
        // 锁内在 governor 判定后记录活动，拒绝请求也不能让回收时间倒退或早于额度观察。
        bucket.last = self.clock.now();
        match decision {
            Ok(Ok(())) => Ok(()),
            _ => Err(CoreError::QuotaExceeded("rate limit exceeded, retry later".into())),
        }
    }
}

#[async_trait]
impl<C> Admission for RateLimiter<C>
where
    C: Clock + Clone + Send + Sync,
    C::Instant: Send,
{
    async fn check(&self, key: &str, cost: f64) -> CoreResult<()> {
        self.check_local(key, cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use governor::clock::FakeRelativeClock;
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    #[derive(Clone)]
    struct PausingClock {
        clock: FakeRelativeClock,
        pause_next: Arc<AtomicBool>,
        sampled: Arc<Barrier>,
        resume: Arc<Barrier>,
    }

    impl Clock for PausingClock {
        type Instant = governor::nanos::Nanos;

        fn now(&self) -> Self::Instant {
            let now = self.clock.now();
            if self.pause_next.swap(false, Ordering::SeqCst) {
                self.sampled.wait();
                self.resume.wait();
            }
            now
        }
    }

    #[test]
    fn paused_clock_read_serializes_activity_and_cannot_refund_capacity() {
        // 分别让 governor 在旧采样之后允许或拒绝请求，覆盖两种活动时间更新。
        for (elapsed, allowed) in [(3, true), (1, false)] {
            let clock = PausingClock {
                clock: FakeRelativeClock::default(),
                pause_next: Arc::new(AtomicBool::new(false)),
                sampled: Arc::new(Barrier::new(2)),
                resume: Arc::new(Barrier::new(2)),
            };
            let limiter =
                Arc::new(RateLimiter::with_clock(AdmissionQuota::new(2, 1.0).unwrap(), 1, clock.clone()).unwrap());
            limiter.check_local("a", 2.0).unwrap();
            clock.pause_next.store(true, Ordering::SeqCst);
            let request = {
                let limiter = limiter.clone();
                std::thread::spawn(move || limiter.check_local("a", 2.0))
            };
            clock.sampled.wait();
            // A 在时刻零暂停，B 不得越过同一把锁在时刻三耗尽桶后再被 A 回写旧时间。
            let activity_is_serialized = limiter.buckets.try_lock().is_err();
            clock.clock.advance(Duration::from_secs(elapsed));
            // 旧实现若在锁外采样，确定性插入 B 的耗尽操作，复现评审指出的交错。
            if !activity_is_serialized && allowed {
                limiter.check_local("a", 2.0).unwrap();
            }
            clock.resume.wait();
            let decision = request.join().unwrap();
            assert!(
                matches!(limiter.check_local("b", 2.0), Err(CoreError::QuotaExceeded(_))),
                "key churn must not refund a recently depleted bucket"
            );
            assert!(activity_is_serialized, "clock observations must be serialized with bucket decisions");
            assert_eq!(decision.is_ok(), allowed);
            if !allowed {
                assert!(matches!(decision, Err(CoreError::QuotaExceeded(_))));
            }
            let observed = Duration::from_secs(elapsed);
            assert_eq!(limiter.buckets.lock().unwrap()[&sha256_hex(b"a")].last, observed.into());
            if allowed {
                assert!(matches!(limiter.check_local("a", 2.0), Err(CoreError::QuotaExceeded(_))));
            }
            // 实际活动之后不足完整恢复窗口时，新键不能替换 a；边界到达后才允许回收。
            clock.clock.advance(Duration::from_millis(1999));
            assert!(matches!(limiter.check_local("b", 2.0), Err(CoreError::QuotaExceeded(_))));
            clock.clock.advance(Duration::from_millis(1));
            limiter.check_local("b", 2.0).unwrap();
            assert!(matches!(limiter.check_local("a", 2.0), Err(CoreError::QuotaExceeded(_))));
        }
    }

    #[tokio::test]
    async fn burst_weight_refill_bound_and_safe_eviction() {
        let clock = FakeRelativeClock::default();
        let limiter = RateLimiter::with_clock(AdmissionQuota::new(2, 1.0).unwrap(), 2, clock.clone()).unwrap();
        limiter.check("a", 0.25).await.unwrap();
        limiter.check("a", 1.75).await.unwrap();
        assert!(matches!(limiter.check("a", 0.01).await, Err(CoreError::QuotaExceeded(_))));
        limiter.check("b", 2.0).await.unwrap();
        assert!(limiter.check("c", 1.0).await.is_err());
        clock.advance(Duration::from_millis(500));
        assert!(limiter.check("c", 1.0).await.is_err());
        assert!(limiter.check("a", 0.75).await.is_err());
        limiter.check("a", 0.5).await.unwrap();
        clock.advance(Duration::from_millis(1500));
        limiter.check("c", 1.0).await.unwrap();
        assert_eq!(limiter.buckets.lock().unwrap().len(), 2);
        assert!(limiter.check("a", 1.75).await.is_err(), "reclamation must not refund a depleted bucket");
        clock.advance(Duration::from_secs(3));
        limiter.check("d", 2.0).await.unwrap();
        assert_eq!(limiter.buckets.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn shared_backend_keeps_route_classes_and_delimited_keys_independent() {
        use memoswish_core::rate_limit::{FailureMode, PolicyLimiter};
        use std::sync::Arc;
        let quota = AdmissionQuota::new(2, 1.0).unwrap();
        let backend = Arc::new(RateLimiter::new(2, 1.0));
        let auth =
            PolicyLimiter { backend: backend.clone(), namespace: "auth".into(), quota, failure: FailureMode::Closed };
        let work =
            PolicyLimiter { backend: backend.clone(), namespace: "work".into(), quota, failure: FailureMode::Closed };
        auth.check("tenant-a", 2.0).await.unwrap();
        assert_eq!(auth.check("tenant-a", 1.0).await.unwrap_err().http_status(), 429);
        work.check("tenant-a", 2.0).await.unwrap();
        auth.check("tenant-b", 2.0).await.unwrap();
        let prefix = PolicyLimiter { backend, namespace: "auth:tenant-a".into(), quota, failure: FailureMode::Closed };
        prefix.check("", 2.0).await.unwrap();
    }

    struct Failed(bool);
    #[async_trait]
    impl Admission for Failed {
        async fn check(&self, _: &str, _: f64) -> CoreResult<()> {
            if self.0 {
                Err(CoreError::Unavailable("backend unavailable".into()))
            } else {
                Err(CoreError::QuotaExceeded("denied".into()))
            }
        }
    }

    #[tokio::test]
    async fn open_only_suppresses_unavailable_never_denial_or_invalid_cost() {
        use memoswish_core::rate_limit::{FailureMode, PolicyLimiter};
        use std::sync::Arc;
        let mut p = PolicyLimiter {
            backend: Arc::new(Failed(true)),
            namespace: "auth".into(),
            quota: AdmissionQuota::new(2, 1.0).unwrap(),
            failure: FailureMode::Closed,
        };
        assert_eq!(p.check("a", 1.0).await.unwrap_err().http_status(), 503);
        p.failure = FailureMode::Open;
        p.check("a", 1.0).await.unwrap();
        assert_eq!(p.check("a", f64::NAN).await.unwrap_err().http_status(), 400);
        p.backend = Arc::new(Failed(false));
        assert_eq!(p.check("a", 1.0).await.unwrap_err().http_status(), 429);
    }
}
