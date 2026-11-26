//! 传输适配器共享隐私查询与本人更新。
use crate::Services;
use memoswish_core::{CoreResult, Principal};
use memoswish_protocol::{PrivacyState, PrivacyUpdate};
impl Services {
    pub async fn privacy_state(&self, p: &Principal) -> CoreResult<PrivacyState> {
        self.auth.privacy_state(p).await
    }
    pub async fn update_privacy(&self, p: &Principal, update: &PrivacyUpdate) -> CoreResult<PrivacyState> {
        self.auth.update_privacy(p, update).await
    }
}

impl Services {
    pub async fn report_forwardable_diagnostic(
        &self,
        p: &Principal,
        report: &memoswish_protocol::DiagnosticReport,
    ) -> CoreResult<memoswish_protocol::DiagnosticReceipt> {
        self.limiter.check(&p.tenant_id, 1.0).await?;
        self.auth.accept_forwardable_diagnostic(p, report).await
    }
    pub async fn report_diagnostic(
        &self,
        p: &Principal,
        report: &memoswish_protocol::DiagnosticReport,
    ) -> CoreResult<memoswish_protocol::DiagnosticReceipt> {
        self.limiter.check(&p.tenant_id, 1.0).await?;
        self.auth.accept_diagnostic(p, report).await
    }
}
