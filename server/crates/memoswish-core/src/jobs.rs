//! SQL 持久工作的租约凭证；外部结果不由调度状态推断。

use crate::CoreResult;
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobClaim {
    pub job_id: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableJob {
    pub id: String,
    pub state: String,
    pub attempts: i64,
    pub max_attempts: i64,
}

/// S15 仅执行 asset_upload 类型；其他工作保留各自现行入口。
#[async_trait]
pub trait AssetJobRepo: Send + Sync {
    async fn asset_job(&self, tenant_id: &str, job_id: &str) -> CoreResult<Option<DurableJob>>;
    async fn claim_asset_job(&self, tenant_id: &str, worker: &str, lease_ms: i64) -> CoreResult<Option<JobClaim>>;
    async fn heartbeat_asset_job(&self, tenant_id: &str, claim: &JobClaim, lease_ms: i64) -> CoreResult<()>;
    /// 重试/耗尽同步调度与关联 BGM 终态，不释放配额或删除外部责任。
    async fn retry_asset_job(&self, tenant_id: &str, claim: &JobClaim, delay_ms: i64) -> CoreResult<()>;
    async fn finish_asset_job(&self, tenant_id: &str, claim: &JobClaim) -> CoreResult<()>;
}
