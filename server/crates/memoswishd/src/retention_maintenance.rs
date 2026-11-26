//! 无应用启动副作用的维护命令；不 seed、不启动 HTTP、provider 或后台 worker。

use std::{io::Read, path::Path};

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 1_048_576, "Maintenance input exceeds byte limit");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid maintenance input"))
}

pub async fn retention_sweep(
    config: &crate::Config,
    tenant: &str,
    policy_path: &Path,
    limit: i64,
    apply: bool,
) -> anyhow::Result<memoswish_storage::retention::RetentionReport> {
    require_maintenance(config)?;
    let policy: memoswish_storage::retention::RetentionPolicy = read_json(policy_path)?;
    policy.validate()?;
    crate::directory_lock::acquire_existing(&config.data_dir)?;
    Ok(memoswish_storage::retention::sweep(&config.database_url(), tenant, &policy, limit, apply).await?)
}

pub async fn restore_suppressions(
    config: &crate::Config,
    path: &Path,
    snapshot: &str,
    after: u64,
    through: u64,
) -> anyhow::Result<()> {
    require_maintenance(config)?;
    let batch: memoswish_storage::restore_suppression::SuppressionBatch = read_json(path)?;
    batch.validate(snapshot, after, through)?;
    crate::directory_lock::acquire_existing(&config.data_dir)?;
    memoswish_storage::restore_suppression::replay(&config.database_url(), &batch, snapshot, after, through).await?;
    Ok(())
}

// 角色校验先于输入读取、安装锁及数据库连接；维护操作仍须持有已有安装的生命周期锁。
fn require_maintenance(config: &crate::Config) -> anyhow::Result<()> {
    config.validate()?;
    anyhow::ensure!(config.role.maintains(), "this command requires maintenance role or embedded all_in_one");
    Ok(())
}

/// 显式持久注册运营方策略；不运行扫描或任何 provider。
pub async fn register_retention(config: &crate::Config, tenant: &str, policy_path: &Path) -> anyhow::Result<()> {
    require_maintenance(config)?;
    let policy: memoswish_core::maintenance::RetentionPolicy = read_json(policy_path)?;
    let task = memoswish_core::maintenance::TaskRegistration {
        kind: memoswish_core::maintenance::TaskKind::Retention,
        tenant: tenant.into(),
        policy: Some(policy),
    };
    task.validate()?;
    crate::directory_lock::acquire_existing(&config.data_dir)?;
    let repo = memoswish_storage::open_runtime(&config.database_url(), 1).await?;
    repo.register_maintenance(&task).await?;
    Ok(())
}
