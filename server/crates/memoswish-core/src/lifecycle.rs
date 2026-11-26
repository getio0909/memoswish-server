//! 独立账户与工作区生命周期命令及全局账户授权边界。

use async_trait::async_trait;

use crate::{AccountPrincipal, CoreError, CoreResult, CredentialGenerations, Principal, identity::ErasureJob};

/// 删除必须明确确认当前工作区。
#[derive(Debug, Clone)]
pub struct DeleteWorkspace {
    pub confirmed_tenant_id: String,
}

/// 接受者必须已经是当前工作区的成员；原 owner 转为管理员。
#[derive(Debug, Clone)]
pub struct TransferOwnership {
    pub successor_user_id: String,
}

/// 仅删除显式确认的独占工作区；共享工作区保留。
#[derive(Debug, Clone, Default)]
pub struct CloseAccount {
    pub confirmed_exclusive_workspaces: Vec<String>,
}

/// 仅用于需要第一方工作区会话的破坏性操作。
pub fn require_first_party(p: &Principal) -> CoreResult<CredentialGenerations> {
    if p.scopes.is_some() || !matches!(p.via.as_str(), "session" | "jwt" | "single_user") {
        return Err(CoreError::Forbidden("lifecycle commands require a first-party session".into()));
    }
    p.credential_generations()
}

/// 每个方法独占一个 SQL 事务；返回的清理任务已持久化。
#[async_trait]
pub trait LifecycleRepo: Send + Sync {
    async fn legacy_close_account(&self, p: &Principal) -> CoreResult<Vec<ErasureJob>>;
    async fn close_account_authorized(
        &self,
        p: &AccountAuthority,
        command: &CloseAccount,
    ) -> CoreResult<Vec<ErasureJob>>;
    async fn export_personal(&self, p: &AccountAuthority) -> CoreResult<memoswish_protocol::PersonalAccountExport>;
    async fn export_workspace(&self, p: &Principal) -> CoreResult<memoswish_protocol::WorkspaceExport>;
    async fn revalidate_account_export(&self, p: &AccountAuthority) -> CoreResult<()>;
    async fn revalidate_workspace_export(&self, p: &Principal, api_token_hash: Option<&str>) -> CoreResult<()>;
    async fn leave_workspace(&self, p: &Principal) -> CoreResult<()>;
    async fn delete_workspace(&self, p: &Principal, command: &DeleteWorkspace) -> CoreResult<ErasureJob>;
    async fn transfer_ownership(&self, p: &Principal, command: &TransferOwnership) -> CoreResult<()>;
    async fn close_account(&self, p: &AccountPrincipal, command: &CloseAccount) -> CoreResult<Vec<ErasureJob>>;
}

/// 保留原始第一方凭据；工作区权限不能通过重读当前账户世代升级。
#[derive(Debug, Clone)]
pub enum AccountAuthority {
    Account(AccountPrincipal),
    Workspace(Principal),
}

impl AccountAuthority {
    pub fn user_id(&self) -> &str {
        match self {
            Self::Account(p) => &p.user_id,
            Self::Workspace(p) => &p.user_id,
        }
    }
    pub fn generation(&self) -> CoreResult<i64> {
        match self {
            Self::Account(p) => Ok(p.generation),
            Self::Workspace(p) => Ok(require_first_party(p)?.account),
        }
    }
}
