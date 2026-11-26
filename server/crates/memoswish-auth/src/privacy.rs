//! 第一方更新和所有凭据共同使用的准入检查。
use crate::AuthService;
use memoswish_core::{CoreResult, Principal};
use memoswish_protocol::{PrivacyPolicy, PrivacyState, PrivacyUpdate};
impl AuthService {
    pub fn with_privacy_policy(mut self, policy: PrivacyPolicy) -> CoreResult<Self> {
        memoswish_core::privacy::validate_policy(&policy)?;
        if policy.hosted && self.mode() != memoswish_protocol::DeploymentMode::MultiTenant {
            return Err(memoswish_core::CoreError::invalid(
                "hosted privacy enforcement requires authenticated multi-tenant mode",
            ));
        }
        self.privacy_policy = policy;
        Ok(self)
    }
    pub fn privacy_policy(&self) -> &PrivacyPolicy {
        &self.privacy_policy
    }
    pub async fn privacy_state(&self, p: &Principal) -> CoreResult<PrivacyState> {
        self.repo.privacy_state(&p.tenant_id, p).await
    }
    pub async fn update_privacy(&self, p: &Principal, update: &PrivacyUpdate) -> CoreResult<PrivacyState> {
        self.repo.privacy_update(&p.tenant_id, p, &self.privacy_policy, update).await
    }
    pub async fn require_privacy_collection(&self, p: &Principal) -> CoreResult<()> {
        if p.via == "jwt" {
            self.legacy_allowed()?;
        }
        // 自托管也复核原始凭据；此入口同时覆盖 MCP/stdio 的工具和资源准入。
        if matches!(p.via.as_str(), "session" | "api_token" | "mcp_oauth" | "jwt") {
            self.repo.access_authorize(&p.tenant_id, p).await?;
        }
        if self.privacy_policy.hosted {
            self.repo.privacy_admit(&p.tenant_id, p, &self.privacy_policy, None, None).await?;
        }
        Ok(())
    }
    pub async fn admit_privacy_purpose(&self, p: &Principal, purpose: &str, revision: Option<i64>) -> CoreResult<i64> {
        self.repo.privacy_admit(&p.tenant_id, p, &self.privacy_policy, Some(purpose), revision).await
    }
}

impl AuthService {
    pub async fn accept_diagnostic(
        &self,
        p: &Principal,
        report: &memoswish_protocol::DiagnosticReport,
    ) -> CoreResult<memoswish_protocol::DiagnosticReceipt> {
        self.repo.diagnostic_insert(&p.tenant_id, p, &self.privacy_policy, report).await
    }
    pub async fn accept_forwardable_diagnostic(
        &self,
        p: &Principal,
        report: &memoswish_protocol::DiagnosticReport,
    ) -> CoreResult<memoswish_protocol::DiagnosticReceipt> {
        self.repo.diagnostic_receive(&p.tenant_id, p, &self.privacy_policy, report, true).await
    }
    pub async fn dispatch_diagnostic(
        &self,
        p: &Principal,
        report: &memoswish_protocol::DiagnosticReport,
    ) -> CoreResult<bool> {
        self.repo.diagnostic_dispatch(&p.tenant_id, p, &self.privacy_policy, report).await
    }
}
