//! 可复用的服务端组装入口；宿主拥有 Tokio 运行时、监听器和关闭信号。
//! embedded 安装写锁持续至进程退出；horizontal 角色不创建本地安装。

mod account;
mod admin;
mod admission;
mod api;
mod app;
mod asset_maintenance;
mod auth_defenses;
mod config;
mod directory_lock;
mod key_rotation;
#[cfg(feature = "mcp-oauth")]
mod oauth;
#[cfg(all(test, feature = "mcp-oauth"))]
mod oauth_tests;
#[cfg(feature = "oidc")]
mod oidc;
#[cfg(all(test, feature = "oidc"))]
mod oidc_tests;
mod retention_maintenance;
mod seed;
mod sessions;
mod snapshot;

#[cfg(test)]
mod account_tests;
#[cfg(test)]
mod feature_tests;
#[cfg(test)]
#[path = "../../../../scripts/gen-references-rs/mod.rs"]
mod generated_refs;
#[cfg(test)]
mod stdio_tests;
#[cfg(test)]
mod tests;

mod bootstrap;
pub mod deployment;
mod health;
mod lifecycle;
mod metrics;
mod runtime;
pub use bootstrap::{migrate, migrate_until};

pub use admission::AdmissionConfig;
pub use auth_defenses::ProxyTrust;
pub use config::{Config, McpConfig, ObjectStoreConfig, TtsConfig};
pub use diagnostics::ForwardingConfig as DiagnosticForwardingConfig;
pub use runtime::Daemon;

/// 窄维护入口；仓储操作先持有进程生命周期安装锁，不启动应用清理。
pub mod maintenance {
    pub use crate::asset_maintenance::verify_asset;
    pub use crate::key_rotation::rotate;
    pub use crate::password_recovery::recover as recover_password;
    pub use crate::retention_maintenance::{register_retention, restore_suppressions, retention_sweep};
    pub use crate::snapshot::write_profile_config;

    /// 比较观察到的修订版本重排耗尽任务，不消费外部证据或执行恢复。
    pub async fn requeue_erasure(config: &crate::Config, job_id: &str, expected_revision: i64) -> anyhow::Result<()> {
        config.validate()?;
        let repo = if config.profile == crate::deployment::Profile::Embedded {
            crate::directory_lock::acquire(&config.data_dir)?;
            memoswish_storage::connect(&config.database_url(), config.database_max_connections()?).await?
        } else {
            memoswish_storage::open_runtime(&config.database_url(), config.database_max_connections()?).await?
        };
        repo.requeue_erasure(job_id, expected_revision).await?;
        Ok(())
    }

    /// 已有安装的只读诊断；锁必须先于连接，不迁移或创建安装目录。
    pub async fn content_orphan_report(
        config: &crate::Config,
    ) -> anyhow::Result<Vec<memoswish_storage::ownership::OrphanCount>> {
        crate::directory_lock::acquire_existing(&config.data_dir)?;
        Ok(memoswish_storage::ownership::content_orphan_report(&config.database_url()).await?)
    }
}

// 既有内部回归继续通过同一生命周期实现验证。
#[cfg(test)]
use runtime::{drain_background, serve_stdio};

mod content_lifecycle;
mod privacy;

#[cfg(test)]
mod privacy_tests;

mod password_mail;
mod password_routes;
pub use password_mail::{PasswordProfile, SmtpConfig};

mod password_recovery;

mod diagnostics;
#[cfg(test)]
mod diagnostics_tests;
mod library;
mod maintenance_scheduler;
#[cfg(test)]
mod password_tests;

mod access;
mod learning_controls;

#[cfg(test)]
mod test_environment {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/test-environment.rs"));
}
