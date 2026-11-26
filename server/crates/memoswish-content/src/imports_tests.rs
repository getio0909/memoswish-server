//! 完成提交越过心跳周期时仍以带围栏事务结果为准。
use super::*;
use memoswish_core::{Principal, Role, repo::*};
use memoswish_storage::sqlite::SqliteRepository;
use std::sync::Arc;

#[tokio::test]
async fn import_completion_stops_heartbeat_and_preserves_expiry_fence() {
    let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
    repo.upsert_tenant(&TenantRecord {
        id: "local".into(),
        name: "Local".into(),
        plan: "self_hosted".into(),
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: "usr_local".into(),
        tenant_id: "local".into(),
        email: "local@example.com".into(),
        display_name: "Owner".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    let service = ContentService::new(repo.clone());
    let p = Principal::local_owner("test");
    for expired in [false, true] {
        let work = service.prepare_deck_pack(&p, memoswish_protocol::examples::sample_deck_pack(), false).unwrap();
        let op = repo
            .accept_import(
                &ImportAuthority::capture(&p, None),
                if expired { "expired" } else { "complete" },
                &memoswish_core::ids::sha256_hex(b"completion-test"),
                &work,
                None,
                2,
            )
            .await
            .unwrap();
        let claim = repo.claim_import("local", &op.id, LEASE_MS).await.unwrap().unwrap();
        if expired {
            let result = ContentService::under_import_lease(
                async {
                    service.execute_import("local", &claim).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='local' AND id=$1")
                        .bind(&claim.job_id)
                        .execute(repo.pool())
                        .await
                        .unwrap();
                    Ok(())
                },
                service.maintain_import_lease("local", &claim),
                async { repo.commit_import("local", &claim).await.map(|_| ()) },
            )
            .await;
            assert!(matches!(result, Err(CoreError::Conflict(_))));
            assert_eq!(repo.import_operation("local", &op.id).await.unwrap().outcome, "pending");
            continue;
        }
        let (heartbeat_owner, mut heartbeat_dropped) = tokio::sync::oneshot::channel::<()>();
        let (committed, observed) = tokio::sync::oneshot::channel();
        let (release, held) = tokio::sync::oneshot::channel();
        let owned = service.clone();
        let claim2 = claim.clone();
        let mut task = tokio::spawn(async move {
            ContentService::under_import_lease(
                owned.execute_import("local", &claim2),
                async {
                    let _heartbeat_owner = heartbeat_owner;
                    owned.maintain_import_lease("local", &claim2).await
                },
                async {
                    assert!(
                        matches!(heartbeat_dropped.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Closed)),
                        "heartbeat must be dropped before completion starts"
                    );
                    owned.repo.commit_import("local", &claim2).await?;
                    committed.send(()).unwrap();
                    held.await.unwrap();
                    Ok(())
                },
            )
            .await
        });
        tokio::select! {biased; result=&mut task=>panic!("completion failed before barrier: {result:?}"), result=observed=>result.unwrap()}
        assert!(matches!(repo.heartbeat_import("local", &claim, LEASE_MS).await, Err(CoreError::Conflict(_))));
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(LEASE_MS as u64)).await;
        tokio::select! { biased; result=&mut task=>panic!("completion was cancelled: {result:?}"), _=tokio::task::yield_now()=>{} }
        // 已验证完成任务跨过续租周期仍存活；后续真实 SQL 不使用自动推进的时钟。
        tokio::time::resume();
        release.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(repo.import_operation("local", &op.id).await.unwrap().outcome, "committed");
    }
}
