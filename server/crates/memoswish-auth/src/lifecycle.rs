//! 第一方会话与内部生命周期命令的认证边界。

use memoswish_core::{AccountPrincipal, CoreError, CoreResult, Principal, identity::ErasureJob, lifecycle::*};
use memoswish_protocol::DeploymentMode;

use crate::AuthService;

impl AuthService {
    fn lifecycle_session(&self, p: &Principal) -> CoreResult<()> {
        require_first_party(p)?;
        if p.via == "single_user"
            && (self.cfg.mode != DeploymentMode::SingleUser
                || p.tenant_id != memoswish_core::ids::LOCAL_TENANT_ID
                || p.user_id != memoswish_core::ids::LOCAL_USER_ID)
        {
            return Err(CoreError::Forbidden("invalid single-user lifecycle session".into()));
        }
        Ok(())
    }

    pub async fn leave_workspace(&self, p: &Principal) -> CoreResult<()> {
        self.lifecycle_session(p)?;
        if self.cfg.mode == DeploymentMode::SingleUser
            && p.user_id == memoswish_core::ids::LOCAL_USER_ID
            && p.tenant_id == memoswish_core::ids::LOCAL_TENANT_ID
        {
            return Err(CoreError::Conflict("local workspace departure requires CloseAccount".into()));
        }
        self.repo.leave_workspace(p).await
    }

    pub async fn delete_workspace(&self, p: &Principal, command: &DeleteWorkspace) -> CoreResult<ErasureJob> {
        self.lifecycle_session(p)?;
        if self.cfg.mode == DeploymentMode::SingleUser && p.tenant_id == memoswish_core::ids::LOCAL_TENANT_ID {
            return Err(CoreError::Conflict("local workspace deletion requires CloseAccount".into()));
        }
        self.repo.delete_workspace(p, command).await
    }

    pub async fn transfer_ownership(&self, p: &Principal, command: &TransferOwnership) -> CoreResult<()> {
        self.lifecycle_session(p)?;
        self.repo.transfer_ownership(p, command).await
    }

    pub async fn close_account(&self, p: &AccountPrincipal, command: &CloseAccount) -> CoreResult<Vec<ErasureJob>> {
        // 活跃单用户账户不能在保留 local 的同时消失，否则启动引导会尝试恢复该账户。
        if self.cfg.mode == DeploymentMode::SingleUser
            && p.user_id == memoswish_core::ids::LOCAL_USER_ID
            && !command
                .confirmed_exclusive_workspaces
                .iter()
                .any(|tenant| tenant == memoswish_core::ids::LOCAL_TENANT_ID)
        {
            return Err(CoreError::Conflict(
                "single-user account closure requires exclusive local workspace confirmation".into(),
            ));
        }
        self.repo.close_account(p, command).await
    }
}

impl AuthService {
    /// 统一第一方边界同时支持账户根及经过验证的无 scope 工作区会话。
    pub async fn authenticate_lifecycle_account(&self, token: Option<&str>) -> CoreResult<AccountAuthority> {
        if let Some(token) = token
            && let Ok(account) = self.authenticate_account(token).await
        {
            return Ok(AccountAuthority::Account(account));
        }
        let p = self.authenticate(token).await?;
        self.lifecycle_session(&p)?;
        Ok(AccountAuthority::Workspace(p))
    }

    pub async fn close_account_authorized(
        &self,
        p: &AccountAuthority,
        command: &CloseAccount,
    ) -> CoreResult<Vec<ErasureJob>> {
        if self.cfg.mode == DeploymentMode::SingleUser
            && p.user_id() == memoswish_core::ids::LOCAL_USER_ID
            && !command.confirmed_exclusive_workspaces.iter().any(|t| t == memoswish_core::ids::LOCAL_TENANT_ID)
        {
            return Err(CoreError::Conflict("single-user closure requires local confirmation".into()));
        }
        self.repo.close_account_authorized(p, command).await
    }

    pub async fn legacy_close_account(&self, p: &Principal) -> CoreResult<Vec<ErasureJob>> {
        self.lifecycle_session(p)?;
        self.repo.legacy_close_account(p).await
    }
}

impl AuthService {
    pub async fn export_personal(&self, p: &AccountAuthority) -> CoreResult<memoswish_protocol::PersonalAccountExport> {
        self.repo.export_personal(p).await
    }
    pub async fn export_workspace(&self, p: &Principal) -> CoreResult<memoswish_protocol::WorkspaceExport> {
        self.repo.export_workspace(p).await
    }
}
