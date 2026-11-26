//! 擦除的调度凭证、外部证据与窄维护端口；不依赖可删除的业务父对象。
use crate::{CoreResult, assets::ObjectVersion, identity::ErasureJob, jobs::JobClaim};
use async_trait::async_trait;

#[derive(Clone)]
pub struct ErasureWork {
    pub job: ErasureJob,
    pub progress: String,
    pub state: String,
    pub attempts: i64,
    pub total_attempts: i64,
    pub revision: i64,
    pub max_attempts: i64,
}

/// 清理身份只包含持久来源与物理位置，不以 URL 或前缀猜测版本。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureObject {
    pub source: String,
    pub tenant_id: String,
    pub id: String,
    pub store_id: String,
    pub key: String,
    pub version: ObjectVersion,
}

#[async_trait]
pub trait ErasureRepo: Send + Sync {
    async fn erasure_work(&self, id: &str) -> CoreResult<Option<ErasureWork>>;
    /// 全局维护例外；稳定游标包含 dead/blocked，不自动重置耗尽预算。
    async fn erasure_page(&self, after: &str, limit: i64) -> CoreResult<Vec<ErasureWork>>;
    async fn claim_erasure(&self, id: &str, worker: &str, lease_ms: i64) -> CoreResult<Option<JobClaim>>;
    async fn heartbeat_erasure(&self, claim: &JobClaim, lease_ms: i64) -> CoreResult<()>;
    async fn retry_erasure(&self, claim: &JobClaim) -> CoreResult<()>;
    async fn complete_erasure(&self, claim: &JobClaim) -> CoreResult<()>;
    /// 维护者必须比较观察到的修订版本；活跃 claim 和已完成操作不可重排。
    async fn requeue_erasure(&self, id: &str, expected_revision: i64) -> CoreResult<()>;
    /// 每次推进持久游标，复用原责任；已完成墓碑重新进入核对，不复活 dead 工作。
    async fn reconcile_erasure_tombstones(&self, limit: i64) -> CoreResult<()>;
    async fn erasure_objects(
        &self,
        claim: &JobClaim,
        after: (&str, &str),
        limit: i64,
    ) -> CoreResult<Vec<ErasureObject>>;
    async fn begin_erasure_object(&self, claim: &JobClaim, object: &ErasureObject, store_id: &str) -> CoreResult<()>;
    /// 晚到 DELETE 回执只补充原证据，不授予调度权。
    async fn record_erasure_object(&self, object: &ErasureObject) -> CoreResult<()>;
    async fn erasure_assets_ready(&self, claim: &JobClaim) -> CoreResult<bool>;
    async fn acknowledge_erasure_assets(&self, claim: &JobClaim) -> CoreResult<()>;
    async fn acknowledge_revocation(
        &self,
        claim: &JobClaim,
        ordinal: usize,
        provider: &str,
        ciphertext: &str,
    ) -> CoreResult<()>;
    /// 登记与删除共享序列化锁；登记失败禁止外部 PUT。
    async fn register_managed_put(&self, tenant: &str, store_id: &str, key: &str) -> CoreResult<ErasureObject>;
    async fn prepare_managed_compensation(&self, object: &ErasureObject) -> CoreResult<()>;
    async fn record_managed_put(&self, object: &ErasureObject, version: &ObjectVersion) -> CoreResult<()>;
}
