//! 配额策略（算力 / 调用量限额）。

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use memoswish_core::repo::Repository;
use memoswish_core::{CoreResult, Principal};
use serde::{Deserialize, Serialize};

/// 计量指标。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    /// TTS 合成字符数。
    TtsChars,
    /// MCP 工具调用次数。
    McpCalls,
    /// 卡片总写入次数。
    CardWrites,
}

impl Metric {
    /// 全部受控计量指标列表。
    pub const ALL: [Metric; 3] = [Metric::TtsChars, Metric::McpCalls, Metric::CardWrites];

    pub fn as_str(&self) -> &'static str {
        match self {
            Metric::TtsChars => "tts_chars",
            Metric::McpCalls => "mcp_calls",
            Metric::CardWrites => "card_writes",
        }
    }
}

/// 单项指标的周期用量与上限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageMetricEntry {
    /// 指标标识（`tts_chars` / `mcp_calls` / `card_writes`）。
    pub metric: String,
    /// 当前计费周期内已使用额度。
    pub used: u64,
    /// 当前尚未结算的预留，包含 uncertain。
    #[serde(default)]
    pub held: u64,
    /// 已调用 provider、尚无可结算结果的预留。
    #[serde(default)]
    pub uncertain: u64,
    /// 当前计费周期月度上限；`None` 表示不限额。
    pub limit: Option<u64>,
}

/// 租户配额与月度用量快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSnapshot {
    /// 租户 ID。
    pub tenant_id: String,
    /// 当前生效套餐名称。
    pub plan: String,
    /// 计费周期（`YYYY-MM`）。
    pub period: String,
    /// 各项指标的已用额度与上限。
    pub metrics: Vec<UsageMetricEntry>,
}

/// 当前计费周期（UTC 自然月），例如 `2026-10`。
pub fn current_period() -> String {
    Utc::now().format("%Y-%m").to_string()
}

/// 配额策略：检查并扣减。
#[async_trait]
pub trait QuotaPolicy: Send + Sync {
    /// 策略名，便于日志与 `server-info` 展示。
    fn name(&self) -> &'static str;
    /// 检查剩余额度并原子累加用量；超额时返回 `QuotaExceeded`。
    async fn consume(&self, principal: &Principal, metric: Metric, amount: u64) -> CoreResult<()>;
    /// 查询调用主体所在租户的当前周期配额与用量快照。
    async fn snapshot(&self, principal: &Principal) -> CoreResult<UsageSnapshot>;
    async fn card_write_limit(&self, _tenant: &str) -> CoreResult<Option<i64>> {
        Ok(None)
    }
    /// 准入额度由存储事务与预留一起检查，不伪造后台 Principal。
    async fn tts_limit(&self, _tenant: &str) -> CoreResult<Option<i64>> {
        Ok(None)
    }
}

/// 自托管：不限额，但仍记录用量便于观测。
pub struct Unlimited {
    repo: Option<Arc<dyn Repository>>,
}

impl Unlimited {
    /// 不记录用量。
    pub fn new() -> Self {
        Self { repo: None }
    }

    /// 记录用量但不限额。
    pub fn metered(repo: Arc<dyn Repository>) -> Self {
        Self { repo: Some(repo) }
    }
}

impl Default for Unlimited {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QuotaPolicy for Unlimited {
    fn name(&self) -> &'static str {
        "unlimited"
    }

    async fn consume(&self, principal: &Principal, metric: Metric, amount: u64) -> CoreResult<()> {
        if let Some(repo) = &self.repo {
            repo.add_usage(
                &principal.tenant_id,
                metric.as_str(),
                &current_period(),
                i64::try_from(amount).map_err(|_| memoswish_core::CoreError::invalid("usage amount exceeds i64"))?,
            )
            .await?;
        }
        Ok(())
    }

    async fn snapshot(&self, principal: &Principal) -> CoreResult<UsageSnapshot> {
        let period = current_period();
        let plan = match &self.repo {
            Some(repo) => {
                repo.get_tenant(&principal.tenant_id).await?.map(|t| t.plan).unwrap_or_else(|| "self_hosted".into())
            }
            None => "self_hosted".into(),
        };
        let mut metrics = Vec::with_capacity(Metric::ALL.len());
        for m in Metric::ALL {
            let used = match &self.repo {
                Some(repo) => repo.get_usage(&principal.tenant_id, m.as_str(), &period).await?.max(0) as u64,
                None => 0,
            };
            let (held, uncertain) = match &self.repo {
                Some(repo) if m == Metric::TtsChars => repo.held_speech_usage(&principal.tenant_id, &period).await?,
                Some(repo) if m == Metric::CardWrites => {
                    (repo.held_import_usage(&principal.tenant_id, &period).await?, 0)
                }
                _ => (0, 0),
            };
            metrics.push(UsageMetricEntry {
                metric: m.as_str().to_string(),
                used,
                held: held.max(0) as u64,
                uncertain: uncertain.max(0) as u64,
                limit: None,
            });
        }
        Ok(UsageSnapshot { tenant_id: principal.tenant_id.clone(), plan, period, metrics })
    }
}

#[cfg(feature = "commercial-quota")]
pub use saas::PlanQuota;

#[cfg(feature = "commercial-quota")]
mod saas {
    use super::*;
    use memoswish_core::CoreError;

    /// 商业套餐月度限额：`(tts_chars, mcp_calls, card_writes)`，`None` 表示不限。
    pub fn plan_limits(plan: &str) -> (Option<i64>, Option<i64>, Option<i64>) {
        match plan {
            "free" => (Some(20_000), Some(1_000), Some(2_000)),
            "pro" => (Some(500_000), Some(50_000), Some(100_000)),
            "team" => (Some(5_000_000), Some(500_000), None),
            // self_hosted 及未知套餐（例如运维手动开通的企业版）不限额。
            _ => (None, None, None),
        }
    }

    /// 基于租户套餐与 `usage_counters` 的限额策略。
    pub struct PlanQuota {
        repo: Arc<dyn Repository>,
    }

    impl PlanQuota {
        pub fn new(repo: Arc<dyn Repository>) -> Self {
            Self { repo }
        }
    }

    #[async_trait]
    impl QuotaPolicy for PlanQuota {
        fn name(&self) -> &'static str {
            "plan"
        }

        async fn consume(&self, principal: &Principal, metric: Metric, amount: u64) -> CoreResult<()> {
            let plan =
                self.repo.get_tenant(&principal.tenant_id).await?.map(|t| t.plan).unwrap_or_else(|| "free".into());
            let (tts, mcp, writes) = plan_limits(&plan);
            let limit = match metric {
                Metric::TtsChars => tts,
                Metric::McpCalls => mcp,
                Metric::CardWrites => writes,
            };
            let period = current_period();
            if let Some(limit) = limit {
                let accepted = self
                    .repo
                    .try_add_usage(
                        &principal.tenant_id,
                        metric.as_str(),
                        &period,
                        i64::try_from(amount).map_err(|_| CoreError::invalid("usage amount exceeds i64"))?,
                        limit,
                    )
                    .await?;
                if accepted.is_none() {
                    return Err(CoreError::QuotaExceeded(format!(
                        "{} monthly limit {limit} reached on plan `{plan}`",
                        metric.as_str()
                    )));
                }
                return Ok(());
            }
            self.repo
                .add_usage(
                    &principal.tenant_id,
                    metric.as_str(),
                    &period,
                    i64::try_from(amount)
                        .map_err(|_| memoswish_core::CoreError::invalid("usage amount exceeds i64"))?,
                )
                .await?;
            Ok(())
        }

        async fn card_write_limit(&self, tenant: &str) -> CoreResult<Option<i64>> {
            let plan = self.repo.get_tenant(tenant).await?.map(|t| t.plan).unwrap_or_else(|| "free".into());
            Ok(plan_limits(&plan).2)
        }
        async fn tts_limit(&self, tenant: &str) -> CoreResult<Option<i64>> {
            let plan = self.repo.get_tenant(tenant).await?.map(|t| t.plan).unwrap_or_else(|| "free".into());
            Ok(plan_limits(&plan).0)
        }

        async fn snapshot(&self, principal: &Principal) -> CoreResult<UsageSnapshot> {
            let plan =
                self.repo.get_tenant(&principal.tenant_id).await?.map(|t| t.plan).unwrap_or_else(|| "free".into());
            let (tts, mcp, writes) = plan_limits(&plan);
            let period = current_period();
            let mut metrics = Vec::with_capacity(3);
            for (metric, limit) in [(Metric::TtsChars, tts), (Metric::McpCalls, mcp), (Metric::CardWrites, writes)] {
                let used = self.repo.get_usage(&principal.tenant_id, metric.as_str(), &period).await?.max(0) as u64;
                let (held, uncertain) = if metric == Metric::TtsChars {
                    self.repo.held_speech_usage(&principal.tenant_id, &period).await?
                } else if metric == Metric::CardWrites {
                    (self.repo.held_import_usage(&principal.tenant_id, &period).await?, 0)
                } else {
                    (0, 0)
                };
                metrics.push(UsageMetricEntry {
                    metric: metric.as_str().to_string(),
                    used,
                    held: held.max(0) as u64,
                    uncertain: uncertain.max(0) as u64,
                    limit: limit.map(|v| v.max(0) as u64),
                });
            }
            Ok(UsageSnapshot { tenant_id: principal.tenant_id.clone(), plan, period, metrics })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_storage::sqlite::SqliteRepository;

    #[tokio::test]
    async fn unlimited_metered_snapshot_tracks_usage() {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let policy = Unlimited::metered(repo);
        let p = Principal::local_owner("test");
        policy.consume(&p, Metric::TtsChars, 120).await.unwrap();
        policy.consume(&p, Metric::McpCalls, 3).await.unwrap();

        let snap = policy.snapshot(&p).await.unwrap();
        assert_eq!(snap.tenant_id, p.tenant_id);
        assert_eq!(snap.metrics.len(), 3);
        let tts = snap.metrics.iter().find(|m| m.metric == "tts_chars").unwrap();
        assert_eq!(tts.used, 120);
        assert_eq!(tts.limit, None);
        let mcp = snap.metrics.iter().find(|m| m.metric == "mcp_calls").unwrap();
        assert_eq!(mcp.used, 3);
        assert_eq!(mcp.limit, None);
    }

    #[cfg(feature = "commercial-quota")]
    #[tokio::test]
    async fn plan_quota_snapshot_and_enforcement() {
        use memoswish_core::repo::TenantRecord;

        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let p = Principal::local_owner("test");
        repo.upsert_tenant(&TenantRecord {
            id: p.tenant_id.clone(),
            name: "Free Tenant".into(),
            plan: "free".into(),
            created_at: Utc::now(),
        })
        .await
        .unwrap();

        let policy = PlanQuota::new(repo);
        policy.consume(&p, Metric::McpCalls, 400).await.unwrap();
        let snap = policy.snapshot(&p).await.unwrap();
        assert_eq!(snap.plan, "free");
        let mcp = snap.metrics.iter().find(|m| m.metric == "mcp_calls").unwrap();
        assert_eq!(mcp.used, 400);
        assert_eq!(mcp.limit, Some(1_000));
        assert!(policy.consume(&p, Metric::McpCalls, 700).await.is_err());
        policy.consume(&p, Metric::McpCalls, 599).await.unwrap();
        let (first, second) =
            tokio::join!(policy.consume(&p, Metric::McpCalls, 1), policy.consume(&p, Metric::McpCalls, 1));
        assert_eq!([first, second].iter().filter(|result| result.is_ok()).count(), 1);
        assert!(policy.consume(&p, Metric::McpCalls, u64::MAX).await.is_err());
        let snap = policy.snapshot(&p).await.unwrap();
        assert_eq!(snap.metrics.iter().find(|m| m.metric == "mcp_calls").unwrap().used, 1000);
    }
}
