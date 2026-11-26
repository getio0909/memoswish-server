//! 两个数据库共用发页回执、并发、失败、升级和作用域回归。

use memoswish_core::repo::*;
use memoswish_core::{CoreError, Principal};
use memoswish_protocol::{FeedPage, FeedQuery, examples};

pub(crate) async fn seed(repo: &impl Repository) -> Principal {
    let (rec, _) = crate::learning_conformance::seed(repo).await;
    Principal { tenant_id: rec.tenant_id, user_id: rec.user_id, ..Principal::local_owner("test") }
}

pub(crate) fn request(query: FeedQuery) -> FeedIssuanceRequest {
    FeedIssuanceRequest {
        query,
        new_session_id: format!("sess_{}", memoswish_core::ids::new_id()),
        legacy_request_id: memoswish_core::ids::new_id(),
        now: chrono::Utc::now(),
    }
}

pub(crate) fn first() -> FeedIssuanceRequest {
    request(FeedQuery { request_id: Some(memoswish_core::ids::new_id()), limit: Some(1), ..Default::default() })
}

pub(crate) async fn candidate(
    repo: &impl Repository,
    p: &Principal,
    req: &FeedIssuanceRequest,
    empty: bool,
) -> FeedIssuanceCandidate {
    let FeedIssuanceOutcome::Ready(expected) = repo.feed_issuance(p, req, None).await.unwrap() else {
        panic!("expected unissued state");
    };
    let mut page = examples::sample_feed_page();
    page.session_id = expected.session.id.clone();
    page.next_cursor = format!("fp_{}", memoswish_core::ids::new_id());
    page.generated_at = req.now;
    page.items.truncate(usize::from(!empty));
    for (index, item) in page.items.iter_mut().enumerate() {
        item.slot = expected.session.next_slot + index as u64;
        item.delivery_id = Some(format!("dlv_{}", memoswish_core::ids::new_id()));
    }
    page.prefetch.entries.clear();
    let mut successor = expected.session.clone();
    successor.next_slot += page.items.len() as u64;
    successor.recent_card_ids.extend(page.items.iter().map(|i| i.card.id.clone()));
    successor.updated_at = req.now;
    let policy = DeliveryPolicy::new("test-policy-v1", &serde_json::json!({"test-policy": 1})).unwrap();
    page.mode = Some("learning".into());
    page.policy_version = Some(policy.version.clone());
    FeedIssuanceCandidate { policy: Some(policy), expected, successor, page }
}

pub(crate) fn committed(outcome: FeedIssuanceOutcome) -> FeedPage {
    let FeedIssuanceOutcome::Committed(page) = outcome else { panic!("expected committed page") };
    page
}

pub(crate) fn continuation(page: &FeedPage) -> FeedIssuanceRequest {
    request(FeedQuery {
        session_id: Some(page.session_id.clone()),
        cursor: Some(page.next_cursor.clone()),
        limit: Some(1),
        ..Default::default()
    })
}

pub(crate) async fn suite(repo: &impl Repository, other: &impl Repository) {
    let p = seed(repo).await;
    let req = first();
    let a = candidate(repo, &p, &req, false).await;
    // 在任何持久写入前，真实双库命令保留两种互斥的冲突原因。
    for cause in [
        memoswish_core::observability::FeedRetryCause::StateMismatch,
        memoswish_core::observability::FeedRetryCause::SessionRevision,
    ] {
        let mut stale = a.clone();
        match cause {
            memoswish_core::observability::FeedRetryCause::StateMismatch => stale.expected.controls_epoch += 1,
            memoswish_core::observability::FeedRetryCause::SessionRevision => stale.expected.revision += 1,
            _ => unreachable!(),
        }
        assert_eq!(repo.feed_issuance(&p, &req, Some(&stale)).await.unwrap(), FeedIssuanceOutcome::Retry(cause));
    }
    assert!(repo.get_session(&p.tenant_id, &p.user_id, &a.successor.id).await.unwrap().is_none());
    let mut competing_request = req.clone();
    competing_request.new_session_id = format!("sess_{}", memoswish_core::ids::new_id());
    let mut competing = candidate(other, &p, &competing_request, false).await;
    competing.page.generated_at += chrono::Duration::seconds(1);
    competing.policy = Some(DeliveryPolicy::new("test-policy-v1", &serde_json::json!({"test-policy": 2})).unwrap());
    competing.page.policy_version = Some(competing.policy.as_ref().unwrap().version.clone());
    // 双方候选已固定在同一前驱，再由独立连接并发提交。
    let barrier = tokio::sync::Barrier::new(2);
    let (left, right) = tokio::join!(
        async {
            barrier.wait().await;
            repo.feed_issuance(&p, &req, Some(&a)).await.unwrap()
        },
        async {
            barrier.wait().await;
            other.feed_issuance(&p, &competing_request, Some(&competing)).await.unwrap()
        },
    );
    let page = committed(left);
    assert_eq!(committed(right), page);
    let losing_id = if page.session_id == a.successor.id { &competing.successor.id } else { &a.successor.id };
    assert!(repo.get_session(&p.tenant_id, &p.user_id, losing_id).await.unwrap().is_none());
    assert_eq!(committed(other.feed_issuance(&p, &req, None).await.unwrap()), page);
    let delivery =
        repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().unwrap();
    assert_eq!(Some(&delivery.attribution.delivery_id), page.items[0].delivery_id.as_ref());
    assert_eq!(Some(&delivery.policy.version), page.policy_version.as_ref());
    assert!(repo.get_delivery("other-tenant", &p.user_id, &page.session_id, 0).await.unwrap().is_none());
    assert!(repo.get_delivery(&p.tenant_id, "other-user", &page.session_id, 0).await.unwrap().is_none());
    let protected = repo.get_session(&p.tenant_id, &p.user_id, &page.session_id).await.unwrap().unwrap();
    assert!(matches!(repo.save_session(&protected).await, Err(CoreError::Conflict(_))));
    let next = continuation(&page);
    let b = candidate(repo, &p, &next, false).await;
    let mut competing = b.clone();
    competing.page.next_cursor.push('x');
    let (left, right) =
        tokio::join!(repo.feed_issuance(&p, &next, Some(&b)), other.feed_issuance(&p, &next, Some(&competing)));
    let second = committed(left.unwrap());
    assert_eq!(committed(right.unwrap()), second);
    assert_eq!(second.items[0].slot, page.items[0].slot + 1);
    for mut conflict in [req.clone(), next.clone()] {
        conflict.query.limit = Some(2);
        assert!(matches!(repo.feed_issuance(&p, &conflict, None).await, Err(CoreError::Conflict(_))));
        conflict.query.limit = Some(1);
        conflict.query.deck_id = Some("other-deck".into());
        assert!(matches!(repo.feed_issuance(&p, &conflict, None).await, Err(CoreError::Conflict(_))));
    }
    // 更晚页面的计算与旧 cursor 的重放互不覆盖。
    let third_req = continuation(&second);
    let c = candidate(repo, &p, &third_req, false).await;
    let (old, new) = tokio::join!(repo.feed_issuance(&p, &next, None), other.feed_issuance(&p, &third_req, Some(&c)));
    assert_eq!(committed(old.unwrap()), second);
    let third = committed(new.unwrap());
    let saved = repo.get_session(&p.tenant_id, &p.user_id, &page.session_id).await.unwrap().unwrap();
    assert_eq!(saved.next_slot, 3);
    assert_eq!(committed(repo.feed_issuance(&p, &req, None).await.unwrap()), page);
    assert_eq!(repo.get_session(&p.tenant_id, &p.user_id, &page.session_id).await.unwrap().unwrap(), saved);
    let stranger = seed(repo).await;
    assert!(matches!(repo.feed_issuance(&stranger, &next, None).await, Err(CoreError::SessionExpired)));
    repo.membership_join(&stranger.tenant_id, &p.user_id, memoswish_core::Role::Learner).await.unwrap();
    let mut foreign_tenant = p.clone();
    foreign_tenant.tenant_id = stranger.tenant_id.clone();
    assert!(matches!(repo.feed_issuance(&foreign_tenant, &next, None).await, Err(CoreError::SessionExpired)));
    repo.membership_join(&p.tenant_id, &stranger.user_id, memoswish_core::Role::Learner).await.unwrap();
    let mut other_member = stranger.clone();
    other_member.tenant_id = p.tenant_id.clone();
    assert!(matches!(repo.feed_issuance(&other_member, &next, None).await, Err(CoreError::SessionExpired)));
    let mut foreign_user = p.clone();
    foreign_user.user_id = "missing-user".into();
    assert!(matches!(repo.feed_issuance(&foreign_user, &next, None).await, Err(CoreError::Unauthorized(_))));
    let mut invalid = next.clone();
    invalid.query.cursor = Some("fp_unknown_future".into());
    assert!(matches!(repo.feed_issuance(&p, &invalid, None).await, Err(CoreError::SessionExpired)));
    invalid.query.session_id = Some("missing-session".into());
    assert!(matches!(repo.feed_issuance(&p, &invalid, None).await, Err(CoreError::SessionExpired)));
    assert!(repo.get_session(&p.tenant_id, &p.user_id, "missing-session").await.unwrap().is_none());
    let mut missing_cursor = next.clone();
    missing_cursor.query.cursor = None;
    assert!(matches!(repo.feed_issuance(&p, &missing_cursor, None).await, Err(CoreError::Conflict(_))));
    let mut mixed = req.clone();
    mixed.query.session_id = Some(page.session_id.clone());
    assert!(matches!(repo.feed_issuance(&p, &mixed, None).await, Err(CoreError::Invalid(_))));
    // 删除活卡之后仍恢复首次不可变快照，新发页不能引用已删除卡。
    let missing_card_req = continuation(&third);
    let stale = candidate(repo, &p, &missing_card_req, false).await;
    assert!(repo.delete_card(&p.tenant_id, &page.items[0].card.id).await.unwrap());
    assert_eq!(
        repo.feed_issuance(&p, &missing_card_req, Some(&stale)).await.unwrap(),
        FeedIssuanceOutcome::Retry(memoswish_core::observability::FeedRetryCause::StateMismatch)
    );
    assert_eq!(committed(repo.feed_issuance(&p, &req, None).await.unwrap()), page);
    let empty = candidate(repo, &p, &missing_card_req, true).await;
    let empty_page = committed(repo.feed_issuance(&p, &missing_card_req, Some(&empty)).await.unwrap());
    let empty_req = continuation(&empty_page);
    let second_empty = candidate(repo, &p, &empty_req, true).await;
    assert_eq!(second_empty.expected.revision, empty.expected.revision + 1);
    assert_eq!(second_empty.expected.session.next_slot, empty.expected.session.next_slot);
    let second_empty_page = committed(repo.feed_issuance(&p, &empty_req, Some(&second_empty)).await.unwrap());
    assert_ne!(second_empty_page.next_cursor, empty_page.next_cursor);
    assert_eq!(committed(repo.feed_issuance(&p, &empty_req, None).await.unwrap()), second_empty_page);
}

macro_rules! backend_tests {
    ($repo:ty, $pool:ty, $migrations:literal, $failure:literal, $drop_failure:literal) => {
        async fn feed_upgrade(pool: &$pool) {
            use crate::foundation_conformance::{through, LEGACY_DATA, SNAPSHOTS};
            let full = sqlx::migrate!($migrations);
            through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            through(&full, 17).run(pool).await.unwrap();
            // S11 升级及失败回滚必须保留 S21 已签发的会话族和凭据。
            sqlx::query("INSERT INTO app_sessions(id,user_id,generation,provenance,auth_time,expires_at) VALUES('s21-family','account',7,'password',100,200)")
                .execute(pool).await.unwrap();
            sqlx::query("INSERT INTO app_session_credentials(access_hash,refresh_hash,assurance_hash,session_id,tenant_id,membership_generation,expires_at) VALUES('s21-access','s21-refresh','s21-assurance','s21-family','foundation',0,150)")
                .execute(pool).await.unwrap();
            let session_snapshots = [
                ("app_sessions", "id,user_id,generation,provenance,auth_time,expires_at,revoked"),
                ("app_session_credentials", "access_hash,refresh_hash,assurance_hash,session_id,tenant_id,membership_generation,expires_at,consumed"),
            ];
            let mut snapshots = Vec::new();
            for (table, columns) in SNAPSHOTS.iter().chain(session_snapshots.iter()) {
                let table = if *table == "users" { "user_profiles" } else { table };
                let projection = columns.split(',').map(|c| format!("CAST({c} AS TEXT)")).collect::<Vec<_>>().join(",");
                let rows = sqlx::query(&format!("SELECT {projection} FROM {table} ORDER BY {projection}")).fetch_all(pool).await.unwrap();
                let snapshot: Vec<Vec<Option<String>>> = rows.iter().map(|r| (0..columns.split(',').count()).map(|i| r.get(i)).collect()).collect();
                snapshots.push((table.to_string(), projection, snapshot));
            }
            let mut broken = through(&full, 18);
            let index = broken.migrations.len()-1;
            assert_eq!(broken.migrations[index].version, 18);
            let sql = format!("{}\nSELECT * FROM injected_s11_missing_table;", broken.migrations[index].sql);
            broken.migrations.to_mut()[index] = sqlx::migrate::Migration::new(18, "injected failure".into(), sqlx::migrate::MigrationType::Simple, sql.into(), false);
            assert!(broken.run(pool).await.is_err());
            assert!(sqlx::query("SELECT issuance_revision FROM feed_sessions").fetch_all(pool).await.is_err());
            assert!(sqlx::query("SELECT * FROM feed_page_receipts").fetch_all(pool).await.is_err());
            let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(version, 17);
            through(&full, 21).run(pool).await.unwrap();
            let mut broken_s12 = through(&full, 22);
            let last = broken_s12.migrations.len()-1;
            let sql = format!("{}\nSELECT * FROM injected_s12_missing_table;", broken_s12.migrations[last].sql);
            broken_s12.migrations.to_mut()[last] = sqlx::migrate::Migration::new(22, "injected S12 failure".into(), sqlx::migrate::MigrationType::Simple, sql.into(), false);
            assert!(broken_s12.run(pool).await.is_err());
            assert!(sqlx::query("SELECT attribution_start_slot FROM feed_sessions").fetch_all(pool).await.is_err());
            assert!(sqlx::query("SELECT * FROM feed_deliveries").fetch_all(pool).await.is_err());
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_deliveries").fetch_one(pool).await.unwrap();
            assert_eq!(count, 0);
            let adopted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_sessions WHERE attribution_start_slot IS NOT NULL").fetch_one(pool).await.unwrap();
            assert_eq!(adopted, 0);
            for (table, projection, before) in snapshots {
                let rows = sqlx::query(&format!("SELECT {projection} FROM {table} ORDER BY {projection}")).fetch_all(pool).await.unwrap();
                let after: Vec<Vec<Option<String>>> = rows.iter().map(|r| (0..before.first().map_or(0, Vec::len)).map(|i| r.get(i)).collect()).collect();
                assert_eq!(after, before, "preserved table {table}");
            }
            let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts").fetch_one(pool).await.unwrap();
            assert_eq!(receipts, 0);
            let row = sqlx::query("SELECT issuance_revision,first_request_id,expires_at_ms FROM feed_sessions WHERE tenant_id='foundation' AND id='session'").fetch_one(pool).await.unwrap();
            assert_eq!(row.get::<i64,_>("issuance_revision"), 0);
            assert!(row.get::<Option<String>,_>("first_request_id").is_none());
            let historical = chrono::DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z").unwrap().timestamp_millis();
            assert!((row.get::<i64,_>("expires_at_ms") - historical).abs() <= 1);
        }

        async fn feed_backend_scenarios(repo: &$repo, other: &$repo) {
            use crate::feed_issuance_conformance::*;
            use crate::learning::{TestGate, TestPoint};
            crate::feed_issuance_conformance::suite(repo, other).await;
            s12_session_fences(repo).await;
            // 故障发生在回执 INSERT 之后的会话 UPDATE，真实 SQL 失败必须整体回滚。
            let p = seed(repo).await;
            let req = first();
            let a = candidate(repo, &p, &req, false).await;
            // 同一连接安装与移除故障触发器，避免池内其他连接保留旧 schema。
            let mut failure_connection = repo.pool().acquire().await.unwrap();
            sqlx::raw_sql($failure).execute(&mut *failure_connection).await.expect("install first-page failure trigger");
            assert!(matches!(repo.feed_issuance(&p, &req, Some(&a)).await, Err(CoreError::Internal(_))));
            assert!(repo.get_session(&p.tenant_id, &p.user_id, &a.successor.id).await.unwrap().is_none());
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1")
                .bind(&p.tenant_id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(count, 0);
            let deliveries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_deliveries WHERE tenant_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(deliveries, 0);
            for table in ["learner_preferences", "learner_card_controls"] {
                let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1 AND user_id=$2"))
                    .bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(count, 0, "failed issuance must roll back serving state in {table}");
            }
            sqlx::raw_sql($drop_failure).execute(&mut *failure_connection).await.expect("remove first-page failure trigger");
            let page = committed(repo.feed_issuance(&p, &req, Some(&a)).await.unwrap());
            // 已有会话也不能留下未推进的回执。
            let next = continuation(&page);
            let b = candidate(repo, &p, &next, false).await;
            sqlx::raw_sql($failure).execute(&mut *failure_connection).await.expect("install continuation failure trigger");
            assert!(matches!(repo.feed_issuance(&p, &next, Some(&b)).await, Err(CoreError::Internal(_))));
            assert_eq!(
                repo.get_session(&p.tenant_id, &p.user_id, &page.session_id).await.unwrap().unwrap().next_slot,
                1
            );
            sqlx::raw_sql($drop_failure).execute(&mut *failure_connection).await.expect("remove continuation failure trigger");
            drop(failure_connection);
            committed(repo.feed_issuance(&p, &next, Some(&b)).await.unwrap());
            for point in [TestPoint::AfterInsert, TestPoint::BeforeCommit] {
                let req = first();
                let a = candidate(repo, &p, &req, false).await;
                let gate = TestGate::new(point);
                let mut paused = repo.clone();
                paused.feed_gate = Some(gate.clone());
                let (principal, request, candidate) = (p.clone(), req.clone(), a.clone());
                let writer =
                    tokio::spawn(async move { paused.feed_issuance(&principal, &request, Some(&candidate)).await });
                tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();
                assert!(other.get_session(&p.tenant_id, &p.user_id, &a.successor.id).await.unwrap().is_none());
                assert!(other.get_delivery(&p.tenant_id, &p.user_id, &a.successor.id, a.page.items[0].slot).await.unwrap().is_none());
                writer.abort();
                assert!(writer.await.unwrap_err().is_cancelled());
                let page = committed(other.feed_issuance(&p, &req, Some(&a)).await.unwrap());
                assert_eq!(committed(repo.feed_issuance(&p, &req, None).await.unwrap()), page);
            }
            // 擦除与真实持锁提交重叠，回执只能先完整提交再按精确范围删除。
            for owner in [false, true] {
                use memoswish_core::identity::IdentityRepo;
                let scope = seed(repo).await;
                let peer_id = memoswish_core::ids::new_id();
                repo.insert_user(&UserRecord { id:peer_id.clone(), tenant_id:scope.tenant_id.clone(), email:format!("{peer_id}@example.com"), display_name:"Peer".into(), password_hash:String::new(), role:memoswish_core::Role::Learner, created_at:chrono::Utc::now() }).await.unwrap();
                let peer = memoswish_core::Principal {user_id:peer_id, ..scope.clone()};
                let peer_req = first();
                let peer_candidate = candidate(repo, &peer, &peer_req, false).await;
                let peer_page = committed(repo.feed_issuance(&peer, &peer_req, Some(&peer_candidate)).await.unwrap());
                let personal = repo.account_export(&scope.tenant_id, &scope.user_id, false).await.unwrap();
                assert!(personal["feed_deliveries"].as_array().unwrap().is_empty());
                if owner {
                    sqlx::query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2")
                        .bind(&scope.tenant_id).bind(&scope.user_id).execute(repo.pool()).await.unwrap();
                }
                let req = first();
                let pending = candidate(repo, &scope, &req, false).await;
                let gate = TestGate::new(TestPoint::BeforeCommit);
                let mut paused = repo.clone(); paused.feed_gate = Some(gate.clone());
                let (principal, request, snapshot) = (scope.clone(), req.clone(), pending.clone());
                let writer = tokio::spawn(async move { paused.feed_issuance(&principal, &request, Some(&snapshot)).await });
                tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();
                let (erasing_repo, tenant, user) = (other.clone(), scope.tenant_id.clone(), scope.user_id.clone());
                let erasing = tokio::spawn(async move { erasing_repo.account_erase(&tenant, &user, owner).await });
                observe_feed_overlap(repo).await;
                gate.resume.add_permits(1);
                committed(writer.await.unwrap().unwrap());
                let job = erasing.await.unwrap().unwrap();
                assert!(matches!(repo.feed_issuance(&scope, &req, Some(&pending)).await, Err(CoreError::Unauthorized(_))));
                assert!(repo.get_session(&scope.tenant_id, &scope.user_id, &pending.page.session_id).await.unwrap().is_none());
                assert_eq!(repo.get_session(&peer.tenant_id, &peer.user_id, &peer_page.session_id).await.unwrap().is_some(), !owner);
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2").bind(&scope.tenant_id).bind(&scope.user_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(count, 0);
                let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_deliveries WHERE tenant_id=$1 AND user_id=$2").bind(&scope.tenant_id).bind(&scope.user_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(remaining, 0);
                assert_eq!(repo.get_delivery(&peer.tenant_id, &peer.user_id, &peer_page.session_id, peer_page.items[0].slot).await.unwrap().is_some(), !owner);
                assert!(repo.account_erasure_finish(&job.id).await.is_err());
            }
            // 延迟进入事务的旧主体不能借重新加入后的当前世代获得写权限。
            let delayed = seed(repo).await;
            let delayed_req = first();
            let delayed_candidate = candidate(repo, &delayed, &delayed_req, false).await;
            let gate = TestGate::new(TestPoint::BeforeTransaction);
            let mut paused = repo.clone(); paused.feed_gate = Some(gate.clone());
            let (principal, request, snapshot) = (delayed.clone(), delayed_req.clone(), delayed_candidate.clone());
            let writer = tokio::spawn(async move { paused.feed_issuance(&principal, &request, Some(&snapshot)).await });
            tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();
            repo.membership_remove(&delayed.tenant_id, &delayed.user_id).await.unwrap();
            repo.membership_join(&delayed.tenant_id, &delayed.user_id, memoswish_core::Role::Learner).await.unwrap();
            gate.resume.add_permits(1);
            assert!(matches!(writer.await.unwrap(), Err(CoreError::Unauthorized(_))));
            assert!(repo.get_session(&delayed.tenant_id, &delayed.user_id, &delayed_candidate.page.session_id).await.unwrap().is_none());
            let revoked = seed(repo).await;
            let revoked_req = first();
            let revoked_candidate = candidate(repo, &revoked, &revoked_req, false).await;
            committed(repo.feed_issuance(&revoked, &revoked_req, Some(&revoked_candidate)).await.unwrap());
            sqlx::query("UPDATE account_auth_epochs SET generation=generation+1 WHERE user_id=$1").bind(&revoked.user_id).execute(repo.pool()).await.unwrap();
            assert!(matches!(repo.feed_issuance(&revoked, &revoked_req, None).await, Err(CoreError::Unauthorized(_))));
            // 期限在数据库中持久化，清理有界，首次身份过期后不能重建。
            let expired_req = first();
            let a = candidate(repo, &p, &expired_req, false).await;
            let page = committed(repo.feed_issuance(&p, &expired_req, Some(&a)).await.unwrap());
            sqlx::query("UPDATE feed_sessions SET expires_at_ms=0 WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                .bind(&p.tenant_id)
                .bind(&p.user_id)
                .bind(&page.session_id)
                .execute(repo.pool())
                .await
                .unwrap();
            for request in [&expired_req, &continuation(&page)] {
                assert!(matches!(other.feed_issuance(&p, request, None).await, Err(CoreError::SessionExpired)));
            }
            assert_eq!(repo.expire_feed_sessions(0).await.unwrap(), 0);
            assert_eq!(repo.expire_feed_sessions(1).await.unwrap(), 1);
            assert!(matches!(repo.feed_issuance(&p, &expired_req, None).await, Err(CoreError::SessionExpired)));
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1 AND session_id=$2")
                    .bind(&p.tenant_id)
                    .bind(&page.session_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(count, 0);
            let delivery = repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().unwrap();
            let (mut record, mut state) = crate::learning_conformance::seed(repo).await;
            record.tenant_id = p.tenant_id.clone(); record.user_id = p.user_id.clone();
            record.session_id = page.session_id.clone(); record.event.card_id = page.items[0].card.id.clone();
            record.event.slot = page.items[0].slot; record.event.delivery_id = page.items[0].delivery_id.clone();
            record.application.as_mut().unwrap().issued_delivery = Some(delivery.attribution);
            state.tenant_id = p.tenant_id.clone(); state.user_id = p.user_id.clone(); state.card_id = record.event.card_id.clone();
            assert_eq!(repo.try_apply_learning_event_for_principal(&p, &record, None, &state).await.unwrap(), LearningEventOutcome::Applied);
            assert_eq!(repo.try_apply_learning_event_for_principal(&p, &record, None, &state).await.unwrap(), LearningEventOutcome::Duplicate);
            // 已提交身份的恢复不依赖历史策略仍能解码。
            let mut unavailable = repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().unwrap();
            unavailable.policy.version = "unsupported-future-policy".into();
            sqlx::query("UPDATE feed_deliveries SET body=$1 WHERE tenant_id=$2 AND user_id=$3 AND session_id=$4 AND slot=$5")
                .bind(serde_json::to_string(&unavailable).unwrap()).bind(&p.tenant_id).bind(&p.user_id).bind(&page.session_id).bind(page.items[0].slot as i64)
                .execute(repo.pool()).await.unwrap();
            assert_eq!(repo.recover_learning_event(&p, &record).await.unwrap(), Some(LearningEventOutcome::Duplicate));
            record.event.delivery_id = Some("different".into());
            assert_eq!(repo.recover_learning_event(&p, &record).await.unwrap(), Some(LearningEventOutcome::PayloadConflict));
            // 移除与重新加入不能使已捕获的旧世代写入，其他用户回执保留。
            let peer = seed(repo).await;
            let peer_req = first();
            let peer_page = committed(
                repo.feed_issuance(&peer, &peer_req, Some(&candidate(repo, &peer, &peer_req, false).await))
                    .await
                    .unwrap(),
            );
            assert!(repo.membership_remove(&p.tenant_id, &p.user_id).await.unwrap());
            assert!(repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().is_none());
            assert!(matches!(repo.feed_issuance(&p, &req, Some(&a)).await, Err(CoreError::Unauthorized(_))));
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&p.tenant_id)
                    .bind(&p.user_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(count, 0);
            repo.membership_join(&p.tenant_id, &p.user_id, memoswish_core::Role::Learner).await.unwrap();
            assert!(matches!(repo.feed_issuance(&p, &req, None).await, Err(CoreError::Unauthorized(_))));
            assert_eq!(committed(repo.feed_issuance(&peer, &peer_req, None).await.unwrap()), peer_page);
        }

        async fn s12_session_fences(repo: &$repo) {
            use crate::feed_issuance_conformance::{candidate, committed, continuation, first};
            use memoswish_core::Principal;
            use memoswish_core::session::{SessionFamily, SessionRepo};
            use crate::learning::{TestGate, TestPoint};
            for via in ["jwt", "session"] {
                for phase in ["new", "continue", "replay", "feedback", "duplicate", "conflict", "preview"] {
                    let (mut record, mut memory) = crate::learning_conformance::seed(repo).await;
                    let p = Principal {tenant_id:record.tenant_id.clone(), user_id:record.user_id.clone(), ..Principal::local_owner("test")};
                    let now = chrono::Utc::now().timestamp();
                    let family = SessionFamily {id:memoswish_core::ids::new_id(), user_id:p.user_id.clone(), generation:0, provenance:"password".into(), auth_time:now, expires_at:now+3600, revoked:false};
                    let root = crate::session_conformance::credential(&family, None);
                    repo.session_issue(&family, &root, None).await.unwrap();
                    let credential = crate::session_conformance::credential(&family, Some((p.tenant_id.clone(),0)));
                    repo.session_select(&root.access_hash, &credential).await.unwrap();
                    let mut captured = p.clone();
                    captured.via = via.into();
                    if via == "jwt" { captured.legacy_issued_at = Some(now); }
                    else { captured.session_access_hash = Some(credential.access_hash.clone()); }
                    repo.authorize_feed_preview(&captured).await.unwrap();
                    let req = first();
                    let page = committed(repo.feed_issuance(&captured, &req, Some(&candidate(repo, &captured, &req, false).await)).await.unwrap());
                    let next = if phase == "new" {first()} else {continuation(&page)};
                    let next_candidate = candidate(repo, &captured, &next, false).await;
                    let delivery = repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().unwrap();
                    record.session_id = page.session_id.clone();
                    record.event.card_id = page.items[0].card.id.clone();
                    record.event.slot = page.items[0].slot;
                    record.event.delivery_id = page.items[0].delivery_id.clone();
                    record.application.as_mut().unwrap().issued_delivery = Some(delivery.attribution);
                    memory.card_id = record.event.card_id.clone();
                    if matches!(phase, "duplicate" | "conflict") {
                        assert_eq!(repo.try_apply_learning_event_for_principal(&captured, &record, None, &memory).await.unwrap(), LearningEventOutcome::Applied);
                    }
                    if phase == "conflict" { record.event.delivery_id = Some("changed-delivery".into()); }
                    // 请求已经捕获授权和投递候选，在事务前由另一连接提交全端注销。
                    let gate = TestGate::new(TestPoint::BeforeTransaction);
                    let mut paused = repo.clone();
                    let writer = if matches!(phase, "new" | "continue" | "feedback") {
                        if phase == "feedback" {paused.learning_gate = Some(gate.clone());}
                        else {paused.feed_gate = Some(gate.clone());}
                        let (p, q, c, r, m) = (captured.clone(), next.clone(), next_candidate.clone(), record.clone(), memory.clone());
                        Some(tokio::spawn(async move {
                            if phase == "feedback" {
                                assert_eq!(paused.try_apply_learning_event_for_principal(&p, &r, None, &m).await.unwrap(), LearningEventOutcome::MissingScope);
                            } else {
                                assert!(matches!(paused.feed_issuance(&p, &q, Some(&c)).await, Err(CoreError::Unauthorized(_))));
                            }
                        }))
                    } else {None};
                    if writer.is_some() {tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified()).await.unwrap();}
                    repo.session_revoke_all(&root.access_hash).await.unwrap();
                    if let Some(writer) = writer {gate.resume.add_permits(1);writer.await.unwrap();}
                    assert!(matches!(repo.authorize_feed_preview(&captured).await, Err(CoreError::Unauthorized(_))));
                    assert!(matches!(repo.feed_issuance(&captured, &req, None).await, Err(CoreError::Unauthorized(_))));
                    assert!(matches!(repo.recover_learning_event(&captured, &record).await, Err(CoreError::Unauthorized(_))));
                    assert_eq!(repo.get_session(&p.tenant_id, &p.user_id, &page.session_id).await.unwrap().unwrap().next_slot, 1);
                    if phase == "new" {
                        assert!(repo.get_session(&p.tenant_id, &p.user_id, &next_candidate.page.session_id).await.unwrap().is_none());
                    }
                    assert!(repo.get_delivery(&p.tenant_id, &p.user_id, &next_candidate.page.session_id, 1).await.unwrap().is_none());
                    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM feedback_events WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(count, i64::from(matches!(phase, "duplicate" | "conflict")));
                    // 全端注销只撤销 App 凭据，API Token 域和已有投递证据继续有效。
                    let mut token = p.clone(); token.via = "api_token".into();
                    repo.authorize_feed_preview(&token).await.unwrap();
                    assert_eq!(committed(repo.feed_issuance(&token, &req, None).await.unwrap()),page);
                    if via == "jwt" {
                        let mut missing = token.clone(); missing.via = "jwt".into();
                        assert!(matches!(repo.authorize_feed_preview(&missing).await, Err(CoreError::Unauthorized(_))));
                    }
                }
            }
        }
    };
}
pub(crate) use backend_tests;
