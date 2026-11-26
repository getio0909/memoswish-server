//! 本地口令证明的快照与事务端口；认证前邮箱索引不授予租户权限。
use crate::CoreResult;
use async_trait::async_trait;

#[derive(Clone)]
pub struct PasswordSnapshot {
    pub user_id: String,
    pub email: String,
    pub password_hash: String,
    pub generation: i64,
    pub version: i64,
    pub verified: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChallengePurpose {
    Verify,
    Reset,
}
impl ChallengePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Reset => "reset",
        }
    }
}

/// 仅内部维护入口可以提供 Operator；HTTP 不接受此枚举。
#[derive(Clone, Copy)]
pub enum PasswordMutation<'a> {
    Verify { email: &'a str, digest: &'a str },
    Reset { email: &'a str, digest: &'a str, new_hash: &'a str },
    Change { proof: &'a PasswordSnapshot, access_hash: &'a str, new_hash: &'a str },
    Operator { proof: &'a PasswordSnapshot, new_hash: &'a str },
}

#[async_trait]
pub trait PasswordLifecycleRepo: Send + Sync {
    async fn password_snapshot(&self, email: &str) -> CoreResult<Option<PasswordSnapshot>>;
    /// 验证结果只能保留原快照世代，不能读取新世代来提升旧证明。
    async fn password_proof(&self, proof: &PasswordSnapshot) -> CoreResult<()>;
    /// 先提交摘要，之后才允许投递；每账户每用途最多一个有效证明。
    async fn password_challenge(
        &self,
        proof: &PasswordSnapshot,
        purpose: ChallengePurpose,
        digest: &str,
        ttl: i64,
    ) -> CoreResult<()>;
    /// 匿名恢复的已知和未知邮箱共用注册锁、读取和条件写入路径。
    async fn password_reset_challenge(&self, email: &str, digest: &str, ttl: i64) -> CoreResult<Option<String>>;
    async fn password_mutate(&self, mutation: PasswordMutation<'_>) -> CoreResult<()>;
    /// 全局维护只删除过期摘要，不暴露账户或挑战正文。
    async fn password_cleanup(&self) -> CoreResult<()>;
}
