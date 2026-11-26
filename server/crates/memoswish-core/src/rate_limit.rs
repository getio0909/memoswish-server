//! 异步准入端口与可丢弃基础设施故障策略；不承担 SQL 配额记账。

use std::{num::NonZeroU32, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &str, cost: f64) -> CoreResult<()>;
}

/// 两个适配器共享整数计量与保守舍入，避免 Redis 和本地准入漂移。
#[derive(Clone, Copy, Debug)]
pub struct AdmissionQuota {
    capacity: u32,
    scale: u32,
    cells: NonZeroU32,
    period: Duration,
    ttl: Duration,
}

impl AdmissionQuota {
    pub fn new(capacity: u32, refill: f64) -> CoreResult<Self> {
        if capacity == 0 || !refill.is_finite() || refill <= 0.0 {
            return Err(CoreError::invalid("invalid admission quota"));
        }
        let scale = (u32::MAX / capacity).min(1_000_000);
        let nanos = (1e9 / (refill * f64::from(scale))).ceil();
        let cells = NonZeroU32::new(capacity * scale).ok_or_else(|| CoreError::invalid("invalid admission quota"))?;
        let horizon = nanos * f64::from(cells.get());
        // 有界 TTL 同时约束极慢补充配置，且保证回收不提前恢复耗尽的额度。
        if !(1.0..=1e9).contains(&nanos) || !horizon.is_finite() || horizon > 86_400e9 {
            return Err(CoreError::invalid("admission quota exceeds supported precision or refill horizon"));
        }
        let period = Duration::from_nanos(nanos as u64);
        let ttl = Duration::from_millis((horizon / 1e6).ceil() as u64);
        Ok(Self { capacity, scale, cells, period, ttl })
    }

    pub fn cost_cells(self, cost: f64) -> CoreResult<NonZeroU32> {
        if !cost.is_finite() || cost <= 0.0 || cost > f64::from(self.capacity) {
            return Err(CoreError::invalid("invalid rate limit cost"));
        }
        NonZeroU32::new((cost * f64::from(self.scale)).ceil() as u32)
            .ok_or_else(|| CoreError::invalid("invalid rate limit cost"))
    }

    pub fn scale(self) -> u32 {
        self.scale
    }
    pub fn burst(self) -> NonZeroU32 {
        self.cells
    }
    pub fn period(self) -> Duration {
        self.period
    }
    pub fn ttl(self) -> Duration {
        self.ttl
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    Open,
    #[default]
    Closed,
}

/// 只吞掉明确的基础设施不可用；拒绝、无效输入和程序错误均保持原错误。
pub struct PolicyLimiter {
    pub backend: Arc<dyn RateLimiter>,
    pub namespace: String,
    pub quota: AdmissionQuota,
    pub failure: FailureMode,
}

#[async_trait]
impl RateLimiter for PolicyLimiter {
    async fn check(&self, key: &str, cost: f64) -> CoreResult<()> {
        self.quota.cost_cells(cost)?;
        let key = format!("{}:{}:{}", self.namespace.len(), self.namespace, key);
        match self.backend.check(&key, cost).await {
            Err(CoreError::Unavailable(_)) if matches!(self.failure, FailureMode::Open) => Ok(()),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotas_reject_invalid_and_preserve_fractional_inputs() {
        for (capacity, rate) in [(0, 1.0), (1, 0.0), (1, -1.0), (1, f64::NAN), (1, f64::INFINITY), (1, 1e-20)] {
            assert!(AdmissionQuota::new(capacity, rate).is_err());
        }
        let quota = AdmissionQuota::new(2, 1.0).unwrap();
        assert_eq!(quota.cost_cells(0.25).unwrap().get(), 250_000);
        assert_eq!(quota.cost_cells(1e-9).unwrap().get(), 1);
        for cost in [0.0, -1.0, f64::NAN, f64::INFINITY, 3.0] {
            assert!(quota.cost_cells(cost).is_err());
        }
        assert!(AdmissionQuota::new(u32::MAX, 100_000.0).is_ok());
    }
}
