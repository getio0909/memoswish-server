//! 有界第一方诊断仓储，授权与写入必须和撤回在同一事务中排序。
use crate::{CoreError, CoreResult, Principal};
use memoswish_protocol::{DiagnosticReceipt, DiagnosticReport, PrivacyPolicy};

pub const MAX_REPORT_BYTES: usize = 16 * 1024;
pub const MAX_FRAMES: usize = 32;
pub const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const SUBJECT_CAP: i64 = 100;
pub const INSTALLATION_CAP: i64 = 10_000;

pub fn validate(report: &DiagnosticReport) -> CoreResult<()> {
    let safe = matches!(report.platform.as_str(), "android" | "ios" | "macos" | "linux" | "windows" | "web" | "server")
        && matches!(report.category.as_str(), "flutter" | "dart" | "operation")
        && matches!(report.code.as_str(), "framework_error" | "unhandled_error" | "operation_failed")
        && report.frames.len() <= MAX_FRAMES
        && report.frames.iter().all(|f| matches!(f.as_str(), "presentation" | "data" | "engine" | "domain" | "core"))
        && report.captured_at_ms >= 0
        && report.privacy_revision >= 0
        && (1..=128).contains(&report.purpose_version.len())
        && report.report_id.len() == 32
        && report.report_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && (1..=40).contains(&report.build.len())
        && report.build.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && serde_json::to_vec(report).map(|b| b.len() <= MAX_REPORT_BYTES).unwrap_or(false);
    if !safe {
        return Err(CoreError::invalid("invalid diagnostic report"));
    }
    Ok(())
}

#[async_trait::async_trait]
pub trait DiagnosticRepo: Send + Sync {
    async fn diagnostic_insert(
        &self,
        tenant_id: &str,
        principal: &Principal,
        policy: &PrivacyPolicy,
        report: &DiagnosticReport,
    ) -> CoreResult<DiagnosticReceipt> {
        self.diagnostic_receive(tenant_id, principal, policy, report, false).await
    }
    /// 传输入口显式标记可外发，自动服务器事件沿用仅第一方收件箱。
    async fn diagnostic_receive(
        &self,
        tenant_id: &str,
        principal: &Principal,
        policy: &PrivacyPolicy,
        report: &DiagnosticReport,
        allow_forwarding: bool,
    ) -> CoreResult<DiagnosticReceipt>;
    /// 只读取已接纳的原始授权，发送前仍须执行当前凭据与同意复核。
    async fn diagnostic_recovery(
        &self,
        admission: &crate::maintenance::MaintenanceAdmission,
    ) -> CoreResult<Option<(Principal, DiagnosticReport)>>;
    /// 先持久标记一次性发送意图；取消、丢响应或重启均不重发。
    async fn diagnostic_dispatch(
        &self,
        tenant_id: &str,
        principal: &Principal,
        policy: &PrivacyPolicy,
        report: &DiagnosticReport,
    ) -> CoreResult<bool>;
}
