//! 离线维护仅接受明确账户 ID 和受保护标准输入，不经过 HTTP 或启动恢复扫描。
use crate::Config;
use memoswish_core::password_lifecycle::PasswordMutation;

pub async fn recover(config: &Config, user_id: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.profile == crate::deployment::Profile::Embedded,
        "local password recovery requires embedded profile and stopped writers"
    );
    crate::directory_lock::acquire_existing(&config.data_dir)?;
    let repo = memoswish_storage::open_runtime(&config.database_url(), 1).await?;
    let account =
        repo.account_by_id(user_id).await?.ok_or_else(|| anyhow::anyhow!("recovery account does not exist"))?;
    let proof = repo
        .password_snapshot(&account.email)
        .await?
        .ok_or_else(|| anyhow::anyhow!("recovery account does not exist"))?;
    let runner = memoswish_auth::password::PasswordRunner::new(config.password_work.clone())?;
    let new_hash = runner.hash(password).await?;
    repo.password_mutate(PasswordMutation::Operator { proof: &proof, new_hash: &new_hash }).await?;
    Ok(())
}
