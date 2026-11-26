//! 恢复发现与业务执行分离；扫描凭据释放后由共享排空域持有已接纳页。

use memoswish_core::{CoreError, CoreResult, maintenance::*};
use tokio::sync::{Semaphore, SemaphorePermit};

// 沿用有界工作许可模式，每类至多一页，其他任务类别不等待慢业务。
static RECOVERY_PAGES: [Semaphore; 5] = [const { Semaphore::const_new(1) }; 5];

impl crate::Services {
    pub fn maintenance_work_permit(kind: TaskKind) -> CoreResult<SemaphorePermit<'static>> {
        let index = match kind {
            TaskKind::ImportRecovery => 0,
            TaskKind::SpeechRecovery => 1,
            TaskKind::AttachmentRecovery => 2,
            TaskKind::ErasureRecovery => 3,
            TaskKind::DiagnosticRecovery => 4,
            _ => return Err(CoreError::invalid("unsupported maintenance business task")),
        };
        RECOVERY_PAGES[index]
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("maintenance business page is already in flight".into()))
    }

    pub fn recover_scheduled(&self, kind: TaskKind) -> CoreResult<tokio::task::JoinHandle<CoreResult<()>>> {
        self.require_import_executor()?;
        if !matches!(
            kind,
            TaskKind::ExplanationRecovery
                | TaskKind::ImportRecovery
                | TaskKind::SpeechRecovery
                | TaskKind::AttachmentRecovery
        ) {
            return Err(CoreError::invalid("unsupported application recovery task"));
        }
        let permit = if kind.discovery() { Some(Self::maintenance_work_permit(kind)?) } else { None };
        let services = self.clone();
        self.operations.spawn(async move {
            let _permit = permit.map(std::sync::Arc::new);
            let repo = services.content.import_repository();
            let id = repo.register_maintenance(&TaskRegistration::system(kind)).await?;
            let worker = memoswish_core::ids::new_id();
            let Some(claim) = repo.claim_maintenance(&id, &worker).await? else { return Ok(()) };
            if kind == TaskKind::ExplanationRecovery {
                let result = repo.maintenance_sql_page(&claim).await;
                if result.is_err() {
                    let _ = repo.release_maintenance(&claim, true).await;
                }
                return result;
            }
            let (page, mut failed) = services.admit_scheduled_page(claim).await?;
            for admission in page {
                let work = services.clone();
                let business_permit = _permit.clone();
                // 单项执行继续使用共享准入；shutdown 后尚未开始的业务留给持久恢复。
                let task = services.operations.spawn(async move {
                    let _permit = business_permit;
                    work.recover_admitted(kind, admission).await
                });
                match task {
                    Ok(task) => {
                        if !matches!(task.await, Ok(Ok(()))) {
                            failed = true;
                        }
                    }
                    _ => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                services.pace_scheduled_failure(kind).await;
                return Err(CoreError::internal("maintenance page failed"));
            }
            Ok(())
        })
    }

    /// 一次调用至多一页业务；空尾页只允许一次新 claim 的包裹延续。
    pub async fn admit_scheduled_page(
        &self,
        mut claim: MaintenanceClaim,
    ) -> CoreResult<(Vec<MaintenanceAdmission>, bool)> {
        let repo = self.content.import_repository();
        for round in 0..2 {
            let scanner = async {
                let mut admitted = Vec::new();
                for item in repo.maintenance_discover(&claim).await? {
                    match repo.admit_maintenance_item(&claim, &item).await {
                        Ok(admission) => admitted.push(admission),
                        // 保留先前已提交项；失败页也须先释放扫描器才能执行这些项。
                        Err(_) => return Ok((admitted, true)),
                    }
                }
                Ok((admitted, false))
            };
            let result = under_maintenance_lease(
                scanner,
                maintain_maintenance_lease(repo.as_ref(), &claim),
                |(page, failed)| {
                    let repo = &repo;
                    let claim = &claim;
                    async move {
                        let continuation = if page.is_empty() && !failed {
                            repo.complete_maintenance_cycle(claim).await?
                        } else {
                            repo.release_maintenance(claim, failed).await?;
                            false
                        };
                        Ok((page, failed, continuation))
                    }
                },
            )
            .await;
            let (page, failed, continuation) = match result {
                Ok(result) => result,
                Err(_) => {
                    let _ = repo.release_maintenance(&claim, true).await;
                    return Err(CoreError::internal("maintenance page failed"));
                }
            };
            if !continuation || round == 1 {
                return Ok((page, failed));
            }
            // 释放旧凭据后再竞争；peer 获胜属于正常停止，不修改其进度。
            let Some(next) = repo.claim_maintenance(&claim.task_id, &memoswish_core::ids::new_id()).await? else {
                return Ok((Vec::new(), false));
            };
            claim = next;
        }
        unreachable!()
    }

    /// 扫描级节流只用新凭据；业务失败事务另行约束已接纳项，不依赖此处竞争成功。
    pub async fn pace_scheduled_failure(&self, kind: TaskKind) {
        let repo = self.content.import_repository();
        let Ok(id) = TaskRegistration::system(kind).id() else { return };
        if let Ok(Some(claim)) = repo.claim_maintenance(&id, &memoswish_core::ids::new_id()).await {
            let _ = repo.release_maintenance(&claim, true).await;
        }
    }

    pub async fn recover_admitted(&self, kind: TaskKind, admission: MaintenanceAdmission) -> CoreResult<()> {
        self.require_import_executor()?;
        if kind != admission.kind {
            return Err(CoreError::invalid("maintenance admission kind mismatch"));
        }
        let item = admission.item;
        match kind {
            TaskKind::ImportRecovery => {
                self.content.recover_import_once(&item.tenant, &item.id).await?;
                self.advance_import_followups(&item.tenant, &item.id).await
            }
            TaskKind::SpeechRecovery => self.media.recover_speech_job(&item.tenant, &item.id).await,
            TaskKind::AttachmentRecovery => self.media.recover_attachment(&item.tenant, &item.id).await,
            _ => Err(CoreError::invalid("unsupported application recovery task")),
        }
    }
}

async fn maintain_maintenance_lease(
    repo: &dyn memoswish_core::repo::Repository,
    claim: &MaintenanceClaim,
) -> CoreResult<bool> {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis((LEASE_MS / 3) as u64));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        repo.renew_maintenance(claim).await?;
    }
}

async fn under_maintenance_lease<T, U, C>(
    scanner: impl Future<Output = CoreResult<T>>,
    heartbeat: impl Future<Output = CoreResult<bool>>,
    complete: impl FnOnce(T) -> C,
) -> CoreResult<U>
where
    C: Future<Output = CoreResult<U>>,
{
    let page = tokio::select! { biased; result=scanner=>result?, result=heartbeat=>{ result?; return Err(CoreError::internal("maintenance heartbeat stopped")); } };
    // select 分支结束先丢弃心跳，再提交清除 token 的 fenced 完成事务。
    complete(page).await
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    #[tokio::test]
    async fn maintenance_completion_stops_heartbeat_and_preserves_expiry_fence() {
        for empty in [false, true] {
            let repo = std::sync::Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
            let id = repo.register_maintenance(&TaskRegistration::system(TaskKind::SpeechRecovery)).await.unwrap();
            let claim = repo.claim_maintenance(&id, "completion-test").await.unwrap().unwrap();
            let (heartbeat_owner, mut heartbeat_dropped) = tokio::sync::oneshot::channel::<()>();
            let (committed, observed) = tokio::sync::oneshot::channel();
            let (release, held) = tokio::sync::oneshot::channel();
            let owned = repo.clone();
            let claim2 = claim.clone();
            let mut task = tokio::spawn(async move {
                let owned = &owned;
                let claim2 = &claim2;
                under_maintenance_lease(
                    async {
                        tokio::task::yield_now().await;
                        Ok(empty)
                    },
                    async {
                        let _heartbeat_owner = heartbeat_owner;
                        maintain_maintenance_lease(owned.as_ref(), claim2).await
                    },
                    |empty| async move {
                        assert!(
                            matches!(
                                heartbeat_dropped.try_recv(),
                                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                            ),
                            "heartbeat must be dropped before completion starts"
                        );
                        if empty {
                            owned.complete_maintenance_cycle(claim2).await?;
                        } else {
                            owned.release_maintenance(claim2, false).await?;
                        }
                        committed.send(()).unwrap();
                        held.await.unwrap();
                        Ok(())
                    },
                )
                .await
            });
            tokio::select! {biased; result=&mut task=>panic!("completion failed before barrier: {result:?}"), result=observed=>result.unwrap()}
            assert!(matches!(repo.renew_maintenance(&claim).await, Err(CoreError::Conflict(_))));
            tokio::time::pause();
            tokio::time::advance(std::time::Duration::from_millis(LEASE_MS as u64)).await;
            tokio::select! { biased; result=&mut task=>panic!("completion was cancelled: {result:?}"), _=tokio::task::yield_now()=>{} }
            release.send(()).unwrap();
            task.await.unwrap().unwrap();
            tokio::time::resume();
            // 完成后 token 被清除；下一次领取真实过期的 claim 仍必须拒绝提交。
            sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1")
                .bind(&id)
                .execute(repo.pool())
                .await
                .unwrap();
            let expired = repo.claim_maintenance(&id, "expired-test").await.unwrap().unwrap();
            let repo = &repo;
            let expired = &expired;
            let result = under_maintenance_lease(
                async {
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='' AND id=$1")
                        .bind(&id)
                        .execute(repo.pool())
                        .await
                        .unwrap();
                    Ok(empty)
                },
                maintain_maintenance_lease(repo.as_ref(), expired),
                |empty| async move {
                    if empty {
                        repo.complete_maintenance_cycle(expired).await.map(|_| ())
                    } else {
                        repo.release_maintenance(expired, false).await
                    }
                },
            )
            .await;
            assert!(matches!(result, Err(CoreError::Conflict(_))));
            assert!(repo.claim_maintenance(&id, "replacement-test").await.unwrap().is_some());
        }
    }
}
