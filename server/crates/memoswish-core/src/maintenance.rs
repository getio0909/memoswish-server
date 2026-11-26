//! 有限维护目录与调度凭据；业务 claim、费用及外部回执仍各自负责完成。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

// 沿用既有维护周期及擦除租约上限；续约间隔由租约推导。
pub const CADENCE_MS: i64 = 60_000;
pub const LEASE_MS: i64 = 300_000;
pub const PAGE_SIZE: i64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    FeedExpiry,
    IdentityExpiry,
    #[serde(rename = "oauth_expiry")]
    OAuthExpiry,
    TombstoneReconcile,
    ErasureRecovery,
    ImportRecovery,
    SpeechRecovery,
    AttachmentRecovery,
    ExplanationRecovery,
    DiagnosticRecovery,
    PasswordExpiry,
    Retention,
}

impl TaskKind {
    pub const ALL: &'static [Self] = &[
        Self::FeedExpiry,
        Self::IdentityExpiry,
        Self::OAuthExpiry,
        Self::TombstoneReconcile,
        Self::ErasureRecovery,
        Self::ImportRecovery,
        Self::SpeechRecovery,
        Self::AttachmentRecovery,
        Self::ExplanationRecovery,
        Self::DiagnosticRecovery,
        Self::PasswordExpiry,
        Self::Retention,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeedExpiry => "feed_expiry",
            Self::IdentityExpiry => "identity_expiry",
            Self::OAuthExpiry => "oauth_expiry",
            Self::TombstoneReconcile => "tombstone_reconcile",
            Self::ErasureRecovery => "erasure_recovery",
            Self::ImportRecovery => "import_recovery",
            Self::SpeechRecovery => "speech_recovery",
            Self::AttachmentRecovery => "attachment_recovery",
            Self::ExplanationRecovery => "explanation_recovery",
            Self::DiagnosticRecovery => "diagnostic_recovery",
            Self::PasswordExpiry => "password_expiry",
            Self::Retention => "retention",
        }
    }

    pub fn discovery(self) -> bool {
        matches!(
            self,
            Self::DiagnosticRecovery
                | Self::ErasureRecovery
                | Self::ImportRecovery
                | Self::SpeechRecovery
                | Self::AttachmentRecovery
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub version: u32,
    pub api_metadata_after_expiry_seconds: i64,
    pub failed_tts_payload_after_schedule_seconds: i64,
}

impl RetentionPolicy {
    pub fn validate(&self) -> CoreResult<()> {
        if self.version != 1
            || !(0..=315_360_000).contains(&self.api_metadata_after_expiry_seconds)
            || !(0..=315_360_000).contains(&self.failed_tts_payload_after_schedule_seconds)
        {
            return Err(CoreError::invalid("invalid retention policy version or duration"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TaskRegistration {
    pub kind: TaskKind,
    pub tenant: String,
    pub policy: Option<RetentionPolicy>,
}

impl TaskRegistration {
    pub fn system(kind: TaskKind) -> Self {
        Self { kind, tenant: String::new(), policy: None }
    }

    pub fn validate(&self) -> CoreResult<()> {
        match (&self.kind, &self.policy) {
            (TaskKind::Retention, Some(policy)) => {
                crate::assets::validate_asset_id(&self.tenant)?;
                policy.validate()
            }
            (TaskKind::Retention, None) => Err(CoreError::invalid("retention requires an explicit policy")),
            (_, None) if self.tenant.is_empty() => Ok(()),
            _ => Err(CoreError::invalid("invalid maintenance scope")),
        }
    }

    pub fn id(&self) -> CoreResult<String> {
        self.validate()?;
        Ok(format!("maintenance:{}:{}", self.kind.as_str(), self.tenant))
    }
}

// 不派生 Debug，避免调用方把内部任务身份变成日志标签或诊断正文。
#[derive(Clone)]
pub struct MaintenanceClaim {
    pub task_id: String,
    pub token: String,
    pub worker: String,
    pub kind: TaskKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryItem {
    pub tenant: String,
    pub id: String,
}

// 已接纳单项的持久移交，不含租约或后续发现权。
#[must_use]
pub struct MaintenanceAdmission {
    pub kind: TaskKind,
    pub admission_id: String,
    pub item: DiscoveryItem,
}

#[async_trait]
pub trait MaintenanceRepo: Send + Sync {
    async fn register_maintenance(&self, task: &TaskRegistration) -> CoreResult<String>;
    async fn claim_maintenance(&self, task: &str, worker: &str) -> CoreResult<Option<MaintenanceClaim>>;
    async fn renew_maintenance(&self, claim: &MaintenanceClaim) -> CoreResult<()>;
    async fn release_maintenance(&self, claim: &MaintenanceClaim, failed: bool) -> CoreResult<()>;
    async fn maintenance_tasks(&self, kind: TaskKind, after: &str) -> CoreResult<Vec<String>>;
    async fn maintenance_sql_page(&self, claim: &MaintenanceClaim) -> CoreResult<()>;
    async fn maintenance_discover(&self, claim: &MaintenanceClaim) -> CoreResult<Vec<DiscoveryItem>>;
    async fn admit_maintenance_item(
        &self,
        claim: &MaintenanceClaim,
        item: &DiscoveryItem,
    ) -> CoreResult<MaintenanceAdmission>;
    // 重置空尾页后返回是否仍有原业务责任；调用方最多重新领取一次。
    async fn complete_maintenance_cycle(&self, claim: &MaintenanceClaim) -> CoreResult<bool>;
}
