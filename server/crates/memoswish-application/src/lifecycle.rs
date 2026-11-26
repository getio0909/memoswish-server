//! 生命周期应用门面，外部清理责任由 SQL 持久任务继续承担。

use memoswish_core::{AccountPrincipal, CoreResult, Principal, identity::ErasureJob, lifecycle::*};

use crate::Services;

impl Services {
    pub async fn leave_workspace(&self, p: &Principal) -> CoreResult<()> {
        self.auth.leave_workspace(p).await
    }

    pub async fn delete_workspace(&self, p: &Principal, command: &DeleteWorkspace) -> CoreResult<ErasureJob> {
        self.auth.delete_workspace(p, command).await
    }

    pub async fn transfer_ownership(&self, p: &Principal, command: &TransferOwnership) -> CoreResult<()> {
        self.auth.transfer_ownership(p, command).await
    }

    pub async fn close_account(&self, p: &AccountPrincipal, command: &CloseAccount) -> CoreResult<Vec<ErasureJob>> {
        self.auth.close_account(p, command).await
    }
}

impl Services {
    pub async fn close_account_authorized(
        &self,
        p: &AccountAuthority,
        command: &CloseAccount,
    ) -> CoreResult<Vec<ErasureJob>> {
        self.auth.close_account_authorized(p, command).await
    }
    pub async fn legacy_close_account(&self, p: &Principal) -> CoreResult<Vec<ErasureJob>> {
        self.auth.legacy_close_account(p).await
    }
}

impl Services {
    pub async fn export_personal(&self, p: &AccountAuthority) -> CoreResult<memoswish_protocol::PersonalAccountExport> {
        self.auth.export_personal(p).await
    }
    pub async fn export_workspace(&self, p: &Principal) -> CoreResult<memoswish_protocol::WorkspaceExport> {
        self.auth.export_workspace(p).await
    }
}
