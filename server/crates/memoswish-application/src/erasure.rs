//! 已提交擦除的外部资产执行；每个网络边界之外使用短事务。
use memoswish_core::{
    CoreError, CoreResult, assets::ObjectVersion, jobs::JobClaim, repo::Repository, store::ObjectStore,
};

pub async fn clean_assets(repo: &dyn Repository, store: &dyn ObjectStore, claim: &JobClaim) -> CoreResult<()> {
    let namespace = store.namespace()?;
    let mut after = (String::new(), String::new());
    let mut unresolved = false;
    loop {
        let page = repo.erasure_objects(claim, (&after.0, &after.1), 100).await?;
        if page.is_empty() {
            break;
        }
        for object in &page {
            after = (object.source.clone(), object.id.clone());
            if object.version == ObjectVersion::Unknown {
                unresolved = true;
                continue;
            }
            repo.begin_erasure_object(claim, object, &namespace).await?;
            let version = match &object.version {
                ObjectVersion::VersionId(id) => Some(id.as_str()),
                ObjectVersion::Unversioned => None,
                ObjectVersion::Unknown => unreachable!(),
            };
            store.delete_write(&object.key, version).await?;
            repo.record_erasure_object(object).await?;
        }
    }
    if unresolved || !repo.erasure_assets_ready(claim).await? {
        return Err(CoreError::Conflict("managed writes remain unresolved".into()));
    }
    let work =
        repo.erasure_work(&claim.job_id).await?.ok_or_else(|| CoreError::NotFound("erasure operation".into()))?;
    let tenant = work
        .job
        .tenant_id
        .filter(|_| work.job.purge_assets)
        .ok_or_else(|| CoreError::Forbidden("erasure has no asset authority".into()))?;
    // 已登记写入全部解决之后才扫描历史版本、删除标记和磁盘临时文件。
    store.purge_prefix(&format!("tenants/{tenant}/")).await?;
    repo.acknowledge_erasure_assets(claim).await
}
