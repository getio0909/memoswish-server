//! 上游身份、一次性登录事务与完整账户生命周期。认证前索引为 ADR 0012 的窄例外。
use crate::{
    CoreResult, CredentialGenerations,
    repo::{TenantRecord, UserRecord},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederatedIdentity {
    #[serde(default)]
    pub client_id: String,
    pub issuer: String,
    pub subject: String,
    pub provider: String,
    /// 兼容登录工作区信息；规范身份归属由 user_id 决定。
    pub tenant_id: String,
    pub user_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub created_at: i64,
    #[serde(default)]
    pub authenticated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginAttempt {
    /// 保留关联发起时已验证的旧 JWT 时间；旧行缺失证据时拒绝关联。
    #[serde(default)]
    pub link_legacy_issued_at: Option<i64>,
    #[serde(default)]
    pub link_access_hash: Option<String>,
    pub id: String,
    pub provider: String,
    pub state_hash: String,
    pub launch_hash: String,
    pub browser_hash: String,
    pub nonce: String,
    pub verifier_ciphertext: String,
    pub client_id: String,
    pub return_uri: String,
    pub app_state: String,
    pub challenge: String,
    pub native: bool,
    pub link_tenant: Option<String>,
    pub link_user: Option<String>,
    #[serde(default)]
    pub link_generation: Option<i64>,
    #[serde(default)]
    pub link_membership_generation: Option<i64>,
    #[serde(default)]
    pub link_session_hash: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginHandoff {
    #[serde(default)]
    pub attempt_id: Option<String>,
    pub generation: i64,
    pub pending_identity: Option<String>,
    pub link_session_hash: Option<String>,
    pub hash: String,
    pub provider: String,
    pub tenant_id: String,
    pub user_id: String,
    pub challenge: String,
    pub expires_at: i64,
}

/// 删除任务没有用户外键，数据库擦除提交后仍可重试上游撤销与对象清理。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErasureJob {
    pub id: String,
    pub tenant_id: Option<String>,
    pub purge_assets: bool,
    pub credentials: Vec<(String, String)>,
}

pub type CipherTransform = dyn Fn(&str, &str) -> CoreResult<String> + Send + Sync;

#[async_trait]
pub trait IdentityRepo: Send + Sync {
    async fn identity_reencrypt(&self, transform: &CipherTransform) -> CoreResult<u64>;
    async fn identity_list(&self, tenant_id: &str, user_id: &str) -> CoreResult<Vec<FederatedIdentity>>;
    /// 最近认证、最后登录方式保护和撤销补偿任务在同一事务内执行。
    #[allow(clippy::too_many_arguments)]
    async fn identity_unlink(
        &self,
        tenant_id: &str,
        user_id: &str,
        generations: CredentialGenerations,
        provider: &str,
        session_hash: &str,
        now: i64,
        configured_clients: &[(String, String, Vec<String>)],
    ) -> CoreResult<bool>;
    async fn identity_attempt_insert(&self, a: &LoginAttempt) -> CoreResult<()>;
    async fn identity_attempt(&self, id: &str, state_lookup: bool) -> CoreResult<Option<LoginAttempt>>;
    async fn identity_launch(&self, id: &str, launch_hash: &str, browser_hash: &str, now: i64) -> CoreResult<bool>;
    async fn identity_claim(&self, id: &str, provider: &str, binding: &str, native: bool, now: i64)
    -> CoreResult<bool>;
    /// 全局 issuer/subject 唯一性与账户创建在同一事务中；邮箱碰撞永不自动关联。
    async fn identity_resolve(
        &self,
        identity: &FederatedIdentity,
        new_account: Option<(&TenantRecord, &UserRecord)>,
        link: bool,
        credential: Option<&str>,
        expected_generations: Option<CredentialGenerations>,
        attempt_id: Option<&str>,
    ) -> CoreResult<(String, String, i64)>;
    async fn identity_handoff_insert(&self, h: &LoginHandoff) -> CoreResult<()>;
    async fn identity_handoff_consume(
        &self,
        hash: &str,
        provider: &str,
        challenge: &str,
        now: i64,
    ) -> CoreResult<Option<LoginHandoff>>;
    /// 完成事务内核验规范身份归属、解绑序列与世代，消费事务并登记最近认证。
    async fn identity_complete(
        &self,
        attempt_id: &str,
        tenant_id: &str,
        user_id: &str,
        generations: CredentialGenerations,
        session_hash: &str,
        now: i64,
    ) -> CoreResult<()>;
    async fn identity_complete_account(
        &self,
        attempt_id: &str,
        tenant_id: &str,
        user_id: &str,
        generation: i64,
        session_hash: &str,
        now: i64,
    ) -> CoreResult<()>;
    async fn identity_recent_auth(
        &self,
        tenant_id: &str,
        user_id: &str,
        generations: CredentialGenerations,
        hash: &str,
        expires: i64,
    ) -> CoreResult<()>;
    async fn identity_recent_deadline(
        &self,
        tenant_id: &str,
        user_id: &str,
        generations: CredentialGenerations,
        hash: &str,
    ) -> CoreResult<Option<i64>>;
    async fn identity_check_recent(
        &self,
        tenant_id: &str,
        user_id: &str,
        generations: CredentialGenerations,
        hash: &str,
        now: i64,
    ) -> CoreResult<bool>;
    async fn identity_event(
        &self,
        issuer: &str,
        subject: &str,
        event_hash: &str,
        event_kind: &str,
        event_at: i64,
        now: i64,
    ) -> CoreResult<()>;
    async fn identity_generation(&self, tenant_id: &str, user_id: &str) -> CoreResult<i64>;
    async fn identity_cleanup(&self, now: i64) -> CoreResult<()>;
    async fn account_export(&self, tenant_id: &str, user_id: &str, owner: bool) -> CoreResult<serde_json::Value>;
    async fn account_erase(&self, tenant_id: &str, user_id: &str, owner: bool) -> CoreResult<ErasureJob>;
    async fn account_erasure_jobs(&self) -> CoreResult<Vec<ErasureJob>>;
    async fn account_erasure_finish(&self, id: &str) -> CoreResult<()>;
    async fn account_erased_tenant(&self, tenant_id: &str) -> CoreResult<bool>;
}
