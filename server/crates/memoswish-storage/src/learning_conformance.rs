//! 双数据库原子反馈的相同行为场景；宏保留后端原生 SQL 类型与私有测试屏障。

use memoswish_core::repo::*;
use memoswish_core::{CoreError, Role};
use memoswish_protocol::examples;

fn sample_application(now: chrono::DateTime<chrono::Utc>) -> LearningApplication {
    LearningApplication {
        disposition: LearningDisposition::Scheduled,
        effective_at: Some(now),
        star: true,
        signal_version: "test-signals-v1".into(),
        signal_thresholds: SignalThresholds {
            fast_swipe_ms: 1500,
            reinforce_loops: 2,
            slow_flip_ms: 8000,
            idle_ms: 120000,
        },
        scheduler_algorithm: "FSRS-6".into(),
        scheduler_package_version: "6.6.2".into(),
        scheduler_adapter_version: "test-adapter-v1".into(),
        scheduler_parameters: vec![0.25; 21],
        desired_retention: 0.9,
        chronology_version: "acceptance-sequence-ms-v1".into(),
        day_policy_version: "elapsed-utc-24h-floor-v1".into(),
        issued_delivery: None,
        attribution_source: "acceptance_time_configuration".into(),
    }
}

pub(crate) async fn seed(repo: &impl Repository) -> (FeedbackEventRecord, MemoryState) {
    let tenant = memoswish_core::ids::new_id();
    let user = memoswish_core::ids::new_id();
    let batch = examples::sample_feedback_batch();
    let now = batch.sent_at;
    repo.upsert_tenant(&TenantRecord {
        id: tenant.clone(),
        name: "Atomic".into(),
        plan: "free".into(),
        created_at: now,
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: user.clone(),
        tenant_id: tenant.clone(),
        email: format!("{user}@example.com"),
        display_name: "Atomic".into(),
        password_hash: String::new(),
        role: Role::Learner,
        created_at: now,
    })
    .await
    .unwrap();
    let deck = examples::sample_deck();
    let card = examples::sample_card();
    repo.insert_deck(&tenant, &deck).await.unwrap();
    repo.insert_card(&tenant, &card).await.unwrap();
    let mut event = batch.events[0].clone();
    event.card_id = card.id;
    let rec = FeedbackEventRecord {
        tenant_id: tenant.clone(),
        user_id: user.clone(),
        session_id: batch.session_id,
        event,
        rating: Some(3),
        received_at: now,
        application: Some(sample_application(now)),
    };
    let state = MemoryState {
        tenant_id: tenant,
        user_id: user,
        card_id: rec.event.card_id.clone(),
        stability: 3.0,
        difficulty: 5.0,
        reps: 1,
        lapses: 0,
        exposures: 1,
        last_review: Some(now),
        due: Some(now),
        starred: true,
        last_rating: Some(3),
    };
    (rec, state)
}

pub(crate) async fn snapshot(repo: &impl Repository, rec: &FeedbackEventRecord) -> Option<VersionedMemory> {
    repo.get_versioned_memory(&rec.tenant_id, &rec.user_id, &rec.event.card_id).await.unwrap()
}

pub(crate) async fn identity_and_cas(repo: &impl Repository) {
    use LearningEventOutcome::*;
    let (rec, state) = seed(repo).await;
    assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Applied);
    let initial = snapshot(repo, &rec).await.unwrap();
    assert_eq!(initial.version, 1);
    let mut retry = rec.clone();
    retry.received_at += chrono::Duration::days(1);
    retry.rating = None;
    assert_eq!(repo.try_apply_learning_event(&retry, None, &state).await.unwrap(), Duplicate);
    for field in 0..14 {
        let mut changed = rec.clone();
        match field {
            0 => changed.session_id.push('x'),
            1 => changed.event.card_id.push('x'),
            2 => changed.event.slot += 1,
            3 => changed.event.shown_at += chrono::Duration::nanoseconds(1),
            4 => changed.event.dwell_time_ms += 1,
            5 => changed.event.loop_count += 1,
            6 => changed.event.swipe_velocity += 1.0,
            7 => changed.event.swipe_direction = memoswish_protocol::SwipeDirection::Previous,
            8 => changed.event.flipped = !changed.event.flipped,
            9 => changed.event.double_tapped = !changed.event.double_tapped,
            10 => changed.event.long_pressed = !changed.event.long_pressed,
            11 => changed.event.muted = !changed.event.muted,
            12 => changed.event.delivery_id = Some("changed-delivery".into()),
            _ => changed.event.event_id.push('x'),
        }
        let mut successor = state.clone();
        successor.card_id = changed.event.card_id.clone();
        let result = repo.try_apply_learning_event(&changed, None, &successor).await.unwrap();
        assert_eq!(result, if field == 13 { Retry } else { PayloadConflict }, "field {field}");
    }
    assert_eq!(snapshot(repo, &rec).await.unwrap(), initial);
    let mut mismatch = state.clone();
    mismatch.user_id.push('x');
    assert!(matches!(repo.try_apply_learning_event(&rec, None, &mismatch).await, Err(CoreError::Invalid(_))));
    assert!(repo.try_apply_learning_event(&rec, Some(-1), &state).await.is_err());
    // 兼容保留的低层写入递增版本，旧快照不能覆盖该写入。
    repo.upsert_memory(&state).await.unwrap();
    assert_eq!(snapshot(repo, &rec).await.unwrap().version, 2);
    let mut next = rec.clone();
    next.event.event_id.push('n');
    assert_eq!(repo.try_apply_learning_event(&next, Some(1), &state).await.unwrap(), Retry);
    // 历史事件只按原始类型内容判重，不宣称其投影完成，也不自动重放。
    let mut legacy = rec.clone();
    legacy.event.event_id.push('l');
    assert!(repo.insert_feedback(&legacy).await.unwrap());
    assert_eq!(repo.try_apply_learning_event(&legacy, Some(2), &state).await.unwrap(), Duplicate);
    legacy.event.double_tapped = !legacy.event.double_tapped;
    assert_eq!(repo.try_apply_learning_event(&legacy, Some(2), &state).await.unwrap(), PayloadConflict);
    assert_eq!(snapshot(repo, &rec).await.unwrap().version, 2);
    let mut zero = rec.clone();
    zero.event.event_id.push('z');
    zero.event.swipe_velocity = -0.0;
    assert_eq!(repo.try_apply_learning_event(&zero, Some(2), &state).await.unwrap(), Applied);
    zero.event.swipe_velocity = 0.0;
    assert_eq!(repo.try_apply_learning_event(&zero, None, &state).await.unwrap(), Duplicate);
    zero.event.swipe_velocity = f32::NAN;
    assert!(matches!(repo.try_apply_learning_event(&zero, None, &state).await, Err(CoreError::Invalid(_))));
    // 相同事件 ID 在不同租户/用户的身份空间互相独立。
    let (mut other, mut other_state) = seed(repo).await;
    other.event.event_id = rec.event.event_id.clone();
    assert_eq!(repo.try_apply_learning_event(&other, None, &other_state).await.unwrap(), Applied);
    let other_user = memoswish_core::ids::new_id();
    repo.insert_user(&UserRecord {
        id: other_user.clone(),
        tenant_id: rec.tenant_id.clone(),
        email: format!("{other_user}@example.com"),
        display_name: "Peer".into(),
        password_hash: String::new(),
        role: Role::Learner,
        created_at: rec.received_at,
    })
    .await
    .unwrap();
    other = rec.clone();
    other.user_id = other_user.clone();
    other_state = state.clone();
    other_state.user_id = other_user;
    assert_eq!(repo.try_apply_learning_event(&other, None, &other_state).await.unwrap(), Applied);
    // 缺失用户与卡片在新事件事务中拒绝，不能写下去重标记。
    other.event.event_id.push('m');
    other.user_id.push('m');
    other_state.user_id = other.user_id.clone();
    assert_eq!(repo.try_apply_learning_event(&other, None, &other_state).await.unwrap(), MissingScope);
    other = rec.clone();
    other.event.event_id.push('c');
    other.event.card_id.push('c');
    other_state = state.clone();
    other_state.card_id = other.event.card_id.clone();
    assert_eq!(repo.try_apply_learning_event(&other, None, &other_state).await.unwrap(), MissingCard);
}

macro_rules! learning_tests {
    ($repo:ident, $pool:ty, $migrations:literal, $before:expr, $after:expr, $drop:expr) => {
        use crate::learning::{TestGate, TestPoint};
        use memoswish_core::identity::IdentityRepo;
        use crate::learning_conformance::{seed, snapshot};
        use memoswish_core::repo::LearningEventOutcome::*;

        async fn upgrade_snapshot(pool: &$pool) -> Vec<Vec<Vec<Option<String>>>> {
            let mut result = Vec::new();
            let extra = [
                ("background_jobs", "tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,state,attempts,max_attempts,available_at_ms,lease_until_ms,worker,token,result,error"),
                ("quota_operations", "tenant_id,operation_id,metric,period,amount,state"),
                ("tenant_memberships", "tenant_id,user_id,role,generation"),
            ];
            for (table, columns) in crate::foundation_conformance::SNAPSHOTS.iter().chain(extra.iter()) {
                let table = if *table == "users" { "user_profiles" } else { table };
                let projection = columns.split(',').map(|column| format!("CAST({column} AS TEXT)")).collect::<Vec<_>>().join(",");
                // S19 新增的擦除工作独立验收；此快照仍逐字段保护迁移前的原工作。
                let scope=if table=="background_jobs" {"AND kind<>'erasure'"}else{""};
                let rows = sqlx::query(&format!("SELECT {projection} FROM {table} WHERE 1=1 {scope} ORDER BY {projection}")).fetch_all(pool).await.unwrap();
                result.push(rows.iter().map(|row| (0..columns.split(',').count()).map(|i| row.get(i)).collect()).collect());
            }
            result
        }

        async fn atomic_feedback_upgrade(pool: &$pool) {
            use crate::foundation_conformance::{through, LEGACY_DATA};
            let full = sqlx::migrate!($migrations);
            through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            through(&full, 10).run(pool).await.unwrap();
            sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','s9-preserve','synthesis','s9-preserve','{}','account',7,3,100)").execute(pool).await.unwrap();
            sqlx::query("INSERT INTO quota_operations VALUES('foundation','s9-preserve','tts_chars','2026-11',17,'reserved')").execute(pool).await.unwrap();
            let before = upgrade_snapshot(pool).await;
            let mut broken = through(&full, 11);
            let sql = format!("{}\nSELECT * FROM injected_s9_missing_table;", broken.migrations.last().unwrap().sql);
            broken.migrations.to_mut()[10] = sqlx::migrate::Migration::new(11, "injected failure".into(), sqlx::migrate::MigrationType::Simple, sql.into(), false);
            assert!(broken.run(pool).await.is_err());
            assert_eq!(upgrade_snapshot(pool).await, before);
            let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(version, 10);
            // 失败迁移中的 ALTER 也必须回滚，不能留下半应用的新列。
            assert!(sqlx::query("SELECT projection_version FROM memory_states").fetch_all(pool).await.is_err());
            through(&full, 11).run(pool).await.unwrap();
            through(&full, 11).run(pool).await.unwrap();
            assert_eq!(upgrade_snapshot(pool).await, before);
            through(&full, 14).run(pool).await.unwrap();
            let pre15 = upgrade_snapshot(pool).await;
            let mut broken = through(&full, 15);
            let index = broken.migrations.len() - 1;
            assert_eq!(broken.migrations[index].version, 15);
            let sql = format!("{}\nSELECT * FROM injected_s10_missing_table;", broken.migrations[index].sql);
            broken.migrations.to_mut()[index] = sqlx::migrate::Migration::new(15, "injected failure".into(), sqlx::migrate::MigrationType::Simple, sql.into(), false);
            assert!(broken.run(pool).await.is_err());
            assert_eq!(upgrade_snapshot(pool).await, pre15);
            assert!(sqlx::query("SELECT application_provenance FROM feedback_events").fetch_all(pool).await.is_err());
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            assert_eq!(upgrade_snapshot(pool).await, pre15);
            let unknown: Option<String> = sqlx::query_scalar("SELECT CAST(application_provenance AS TEXT) FROM feedback_events WHERE tenant_id='foundation'").fetch_one(pool).await.unwrap();
            assert!(unknown.is_none());
            let version: i64 = sqlx::query_scalar("SELECT projection_version FROM memory_states WHERE tenant_id='foundation'").fetch_one(pool).await.unwrap();
            assert_eq!(version, 0);
            let hash: Option<String> = sqlx::query_scalar("SELECT payload_hash FROM feedback_events WHERE tenant_id='foundation'").fetch_one(pool).await.unwrap();
            assert!(hash.is_none());
            let repo = $repo { observer: memoswish_core::observability::noop(), pool: pool.clone(), learning_gate: None, feed_gate: None, content_gate: None, lifecycle_gate: None };
            let (rec, state) = seed(&repo).await;
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Applied);
        }

        async fn event_count(repo: &$repo, rec: &FeedbackEventRecord) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM feedback_events WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3")
                .bind(&rec.tenant_id)
                .bind(&rec.user_id)
                .bind(&rec.event.event_id)
                .fetch_one(repo.pool())
                .await
                .unwrap()
        }

        async fn stored_provenance(repo: &$repo, rec: &FeedbackEventRecord) -> Option<LearningEventProvenance> {
            let text: Option<String> = sqlx::query_scalar("SELECT CAST(application_provenance AS TEXT) FROM feedback_events WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3")
                .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id).fetch_one(repo.pool()).await.unwrap();
            text.map(|text| serde_json::from_str(&text).unwrap())
        }

        async fn provenance_and_legacy_precision(repo: &$repo) {
            let (mut rec, mut state) = seed(repo).await;
            rec.event.shown_at += chrono::Duration::nanoseconds(123_456_789);
            rec.received_at += chrono::Duration::nanoseconds(987_654_321);
            let original = repo.get_card(&rec.tenant_id, &rec.event.card_id).await.unwrap().unwrap();
            let change = crate::content_conformance::edit(&original, Some(original.revision), "updated before acceptance");
            let card = repo.mutate_cards(&rec.tenant_id, &[change]).await.unwrap().remove(0);
            assert_eq!(card.revision, original.revision + 1);
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Applied);
            let saved = stored_provenance(repo, &rec).await.unwrap();
            assert_eq!(saved.application, rec.application.clone().unwrap());
            assert_eq!(saved.observed_at, rec.event.shown_at);
            assert_eq!(saved.received_at, rec.received_at);
            assert_eq!(saved.revision_at_acceptance, card.revision);
            assert_eq!((saved.predecessor_version, saved.successor_version), (None, 1));
            let mut retry = rec.clone(); retry.rating = None; retry.received_at += chrono::Duration::days(1);
            retry.application.as_mut().unwrap().desired_retention = 0.8;
            assert_eq!(repo.try_apply_learning_event(&retry, None, &state).await.unwrap(), Duplicate);
            assert_eq!(stored_provenance(repo, &rec).await.unwrap(), saved);
            let mut legacy = rec.clone(); legacy.event.event_id.push('l'); legacy.application = None;
            assert!(repo.insert_feedback(&legacy).await.unwrap());
            assert!(stored_provenance(repo, &legacy).await.is_none());
            let export = repo.account_export(&rec.tenant_id, &rec.user_id, false).await.unwrap();
            assert!(export["feedback_events"].as_array().unwrap().iter().any(|r| r["application_provenance"].is_null()));

            // 模拟旧库更细精度的调度列；未调度接受只更新曝光与收藏，不能重写旧时间。
            sqlx::query("UPDATE memory_states SET last_review='2026-11-01T00:00:00.123456Z',due='2026-11-02T00:00:00.654321Z' WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3")
                .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.card_id).execute(repo.pool()).await.unwrap();
            let before = snapshot(repo, &rec).await.unwrap();
            rec.event.event_id.push('u');
            rec.application.as_mut().unwrap().disposition = LearningDisposition::LateNotScheduled;
            rec.application.as_mut().unwrap().effective_at = None;
            state = before.state.clone(); state.exposures += 1;
            assert_eq!(repo.try_apply_learning_event(&rec, Some(before.version), &state).await.unwrap(), Applied);
            assert_eq!(snapshot(repo, &rec).await.unwrap().state, state);
            let saved = stored_provenance(repo, &rec).await.unwrap();
            assert_eq!((saved.predecessor_version, saved.successor_version), (Some(1), 2));
            assert_eq!(saved.application.disposition, LearningDisposition::LateNotScheduled);
        }

        async fn concurrent_cas(repo: &$repo) {
            for existing in [false, true] {
                let (mut a, mut state) = seed(repo).await;
                if existing {
                    repo.upsert_memory(&state).await.unwrap();
                }
                let expected = snapshot(repo, &a).await.map(|m| m.version);
                state.exposures += u32::from(existing);
                let mut b = a.clone();
                b.event.event_id.push('b');
                // 两个请求明确携带同一个先前快照，强制制造 CAS 冲突。
                let (left, right) = tokio::join!(
                    repo.try_apply_learning_event(&a, expected, &state),
                    repo.try_apply_learning_event(&b, expected, &state)
                );
                let results = [left.unwrap(), right.unwrap()];
                assert_eq!(results.iter().filter(|v| **v == Applied).count(), 1);
                assert_eq!(results.iter().filter(|v| **v == Retry).count(), 1);
                let loser = if results[0] == Retry { &a } else { &b };
                assert_eq!(event_count(repo, loser).await, 0, "failed CAS must roll back its event");
                let fresh = snapshot(repo, &a).await.unwrap();
                let mut successor = fresh.state.clone();
                successor.exposures += 1;
                assert_eq!(
                    repo.try_apply_learning_event(loser, Some(fresh.version), &successor).await.unwrap(),
                    Applied
                );
                assert_eq!(snapshot(repo, &a).await.unwrap().state.exposures, if existing { 3 } else { 2 });
                let saved = snapshot(repo, &a).await;
                a.event.event_id.push('i');
                let version = saved.as_ref().map(|s| s.version);
                let (left, right) = tokio::join!(
                    repo.try_apply_learning_event(&a, version, &successor),
                    repo.try_apply_learning_event(&a, version, &successor)
                );
                assert!(matches!((left.unwrap(), right.unwrap()), (Applied, Duplicate) | (Duplicate, Applied)));
                assert_eq!(event_count(repo, &a).await, 1);
            }
        }

        async fn missing_membership(repo: &$repo) {
            let (rec, state) = seed(repo).await;
            assert!(repo.get_user(&rec.tenant_id, &rec.user_id).await.unwrap().is_some());
            let deleted = sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                .bind(&rec.tenant_id).bind(&rec.user_id).execute(repo.pool()).await.unwrap();
            assert_eq!(deleted.rows_affected(), 1);
            // 全局用户与租户均存在，只有目标成员关系缺失，确保命中成员检查。
            let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=$1")
                .bind(&rec.user_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(users, 1);
            assert!(repo.get_tenant(&rec.tenant_id).await.unwrap().is_some());
            assert!(repo.get_user(&rec.tenant_id, &rec.user_id).await.unwrap().is_none());
            assert!(repo.get_card(&rec.tenant_id, &rec.event.card_id).await.unwrap().is_some());
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), MissingScope);
            assert_eq!(event_count(repo, &rec).await, 0);
            assert!(snapshot(repo, &rec).await.is_none());
        }

        async fn sql_failure_rollback(repo: &$repo) {
            for after_memory in [false, true] {
                let (rec, state) = seed(repo).await;
                // AFTER UPDATE 在 memory 写入后抛真实 SQL 错误；BEFORE INSERT 在事件插入后失败。
                if after_memory {
                    repo.upsert_memory(&state).await.unwrap();
                }
                let prior = snapshot(repo, &rec).await;
                sqlx::raw_sql(if after_memory { $after } else { $before }).execute(repo.pool()).await.unwrap();
                assert!(repo.try_apply_learning_event(&rec, prior.as_ref().map(|v| v.version), &state).await.is_err());
                assert_eq!(event_count(repo, &rec).await, 0);
                assert_eq!(snapshot(repo, &rec).await, prior);
                sqlx::raw_sql($drop).execute(repo.pool()).await.unwrap();
                assert_eq!(
                    repo.try_apply_learning_event(&rec, prior.as_ref().map(|v| v.version), &state).await.unwrap(),
                    Applied
                );
                assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Duplicate);
            }
        }

        async fn cancellation_and_visibility(repo: &$repo) {
            for point in [TestPoint::AfterInsert, TestPoint::BeforeCommit] {
                let (rec, state) = seed(repo).await;
                let gate = TestGate::new(point);
                let mut paused = repo.clone();
                paused.learning_gate = Some(gate.clone());
                let (record, successor) = (rec.clone(), state.clone());
                let writer =
                    tokio::spawn(async move { paused.try_apply_learning_event(&record, None, &successor).await });
                tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();
                // 由另一个连接观察，事务中的事件与投影均不可见。
                assert_eq!(event_count(repo, &rec).await, 0);
                assert!(snapshot(repo, &rec).await.is_none());
                writer.abort();
                assert!(writer.await.unwrap_err().is_cancelled());
                assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Applied);
                // 模拟提交后丢响应：重新获取连接后重传只返回 duplicate。
                assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Duplicate);
                assert_eq!(snapshot(repo, &rec).await.unwrap().version, 1);
                assert_eq!(stored_provenance(repo, &rec).await.unwrap().successor_version, 1);
            }
        }

        async fn erasure_and_card_overlap(repo: &$repo) {
            use memoswish_core::identity::IdentityRepo;
            for owner in [false, true] {
                let (rec, state) = seed(repo).await;
                let (peer, _) = seed(repo).await;
                let uid = memoswish_core::ids::new_id();
                repo.insert_user(&UserRecord { id: uid.clone(), tenant_id: rec.tenant_id.clone(), email: format!("{uid}@example.com"), display_name: "Peer".into(), password_hash: String::new(), role: Role::Learner, created_at: rec.received_at }).await.unwrap();
                let mut member_rec = rec.clone(); member_rec.user_id = uid.clone();
                let mut member_state = state.clone(); member_state.user_id = uid;
                assert_eq!(repo.try_apply_learning_event(&member_rec, None, &member_state).await.unwrap(), Applied);
                if owner {
                    sqlx::query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2")
                        .bind(&rec.tenant_id)
                        .bind(&rec.user_id)
                        .execute(repo.pool())
                        .await
                        .unwrap();
                }
                let gate = TestGate::new(TestPoint::BeforeCommit);
                let mut paused = repo.clone();
                paused.learning_gate = Some(gate.clone());
                let (record, successor) = (rec.clone(), state.clone());
                let writer =
                    tokio::spawn(async move { paused.try_apply_learning_event(&record, None, &successor).await });
                tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();
                // 在写入实际持锁时启动擦除，并轮询到数据库锁屏障（后端函数）。
                let erasing = {
                    let (copy, tid, uid) = (repo.clone(), rec.tenant_id.clone(), rec.user_id.clone());
                    tokio::spawn(async move { copy.account_erase(&tid, &uid, owner).await })
                };
                observe_overlap(repo).await;
                gate.resume.add_permits(1);
                assert_eq!(writer.await.unwrap().unwrap(), Applied);
                let job = erasing.await.unwrap().unwrap();
                assert_eq!(event_count(repo, &rec).await, 0);
                assert!(snapshot(repo, &rec).await.is_none());
                assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), MissingScope);
                assert!(repo.get_user(&peer.tenant_id, &peer.user_id).await.unwrap().is_some());
                assert_eq!(event_count(repo, &member_rec).await, i64::from(!owner));
                assert_eq!(snapshot(repo, &member_rec).await.is_some(), !owner);
                assert_eq!(repo.get_card(&rec.tenant_id, &rec.event.card_id).await.unwrap().is_some(), !owner);
                assert!(repo.account_erasure_finish(&job.id).await.is_err());
            }
            let (mut rec, state) = seed(repo).await;
            let gate = TestGate::new(TestPoint::BeforeCommit);
            let mut paused = repo.clone();
            paused.learning_gate = Some(gate.clone());
            let (record, successor) = (rec.clone(), state.clone());
            let writer = tokio::spawn(async move { paused.try_apply_learning_event(&record, None, &successor).await });
            tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();
            let deleting = {
                let (copy, tid, cid) = (repo.clone(), rec.tenant_id.clone(), rec.event.card_id.clone());
                tokio::spawn(async move { copy.delete_card(&tid, &cid).await })
            };
            observe_overlap(repo).await;
            gate.resume.add_permits(1);
            assert_eq!(writer.await.unwrap().unwrap(), Applied);
            assert!(deleting.await.unwrap().unwrap());
            // 已提交身份先于卡片检查恢复回执，缺卡也不能重新投影或改写载荷。
            let saved = snapshot(repo, &rec).await;
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Duplicate);
            let mut changed = rec.clone();
            changed.event.long_pressed = !changed.event.long_pressed;
            assert_eq!(repo.try_apply_learning_event(&changed, None, &state).await.unwrap(), PayloadConflict);
            assert_eq!(snapshot(repo, &rec).await, saved);
            rec.event.event_id.push('d');
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), MissingCard);
            assert_eq!(event_count(repo, &rec).await, 0);
        }

        async fn atomic_feedback_suite(repo: &$repo) {
            crate::learning_conformance::identity_and_cas(repo).await;
            missing_membership(repo).await;
            provenance_and_legacy_precision(repo).await;
            concurrent_cas(repo).await;
            sql_failure_rollback(repo).await;
            cancellation_and_visibility(repo).await;
            erasure_and_card_overlap(repo).await;
        }
    };
}
pub(crate) use learning_tests;
