//! 第一方会话的认证前哈希索引与账户所有权事务；不复用 API/MCP 凭据域。
use crate::CoreResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionFamily {
    pub id: String,
    pub user_id: String,
    pub generation: i64,
    pub provenance: String,
    pub auth_time: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCredential {
    pub access_hash: String,
    pub refresh_hash: String,
    pub assurance_hash: String,
    pub session_id: String,
    pub tenant_id: Option<String>,
    pub membership_generation: Option<i64>,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct SessionAccess {
    pub family: SessionFamily,
    pub credential: SessionCredential,
}

#[async_trait]
pub trait SessionRepo: Send + Sync {
    /// MCP/stdio 保留主体的后续使用仍须复核原始凭据，不能只检查角色。
    async fn access_authorize(&self, tenant_id: &str, principal: &crate::Principal) -> CoreResult<()>;

    /// 账户会话窄查询；持有原始凭据，分页只返回本人摘要。
    async fn access_page(
        &self,
        access_hash: &str,
        kind: AccessKind,
        after: &str,
        limit: u32,
    ) -> CoreResult<memoswish_protocol::AccessPage>;
    /// 同事务重验账户会话和目标所有权；非会话目标必须显式绑定租户。
    async fn access_revoke(
        &self,
        access_hash: &str,
        kind: AccessKind,
        tenant_id: Option<&str>,
        id: &str,
    ) -> CoreResult<bool>;

    /// 新注册的租户、账户、成员及根会话必须整体提交。
    async fn session_register(
        &self,
        tenant: &crate::repo::TenantRecord,
        user: &crate::repo::UserRecord,
        family: &SessionFamily,
        credential: &SessionCredential,
    ) -> CoreResult<()>;
    /// 根会话授权的账户窄查询，发现结果不授予工作区权限。
    async fn session_memberships(&self, access_hash: &str) -> CoreResult<Vec<memoswish_protocol::MembershipSummary>>;
    /// 同事务撤销第一方会话族并单调推进旧 JWT 屏障。
    async fn session_revoke_all(&self, access_hash: &str) -> CoreResult<()>;
    /// 在注册锁内重验原始 JWT 证据；预签发时间不能晚于锁后数据库时间。
    async fn legacy_session_authorize(
        &self,
        user_id: &str,
        generation: i64,
        issued_at: i64,
        successor_issued_at: Option<i64>,
        workspace: Option<(&str, i64)>,
    ) -> CoreResult<()>;
    /// 完成关联并消费 attempt，保持原会话与最近认证期限。
    async fn session_link_ack(&self, access_hash: &str, attempt: &str) -> CoreResult<()>;
    /// 认证前窄索引，只返回当前有效账户及捕获的工作区权限。
    async fn session_access(&self, access_hash: &str) -> CoreResult<SessionAccess>;
    /// 完成 OIDC 时消费 attempt、应用待关联身份与签发凭据在同一事务内提交。
    async fn session_issue(
        &self,
        family: &SessionFamily,
        credential: &SessionCredential,
        attempt: Option<&str>,
    ) -> CoreResult<()>;
    /// 保留账户根，显式工作区选择不重新认证或延长认证时间。
    async fn session_select(&self, access_hash: &str, credential: &SessionCredential) -> CoreResult<()>;
    /// 消费父凭据和写入后继同事务；已消费父凭据触发持久族撤销。
    async fn session_rotate(
        &self,
        refresh_hash: &str,
        next_access_hash: &str,
        next_refresh_hash: &str,
        assurance_hash: &str,
        access_ttl: i64,
    ) -> CoreResult<SessionAccess>;
    async fn session_list(&self, access_hash: &str) -> CoreResult<Vec<SessionFamily>>;
    /// 只允许凭当前有效第一方 access 撤销同账户的目标会话。
    async fn session_revoke(&self, access_hash: &str, session_id: &str) -> CoreResult<bool>;
}

/// 清单类别只选择固定 SQL，不把传输路径拼进查询。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Sessions,
    ApiTokens,
    Grants,
}
impl AccessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sessions => "sessions",
            Self::ApiTokens => "api-tokens",
            Self::Grants => "grants",
        }
    }
}
