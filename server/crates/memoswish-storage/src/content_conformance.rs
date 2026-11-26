//! 双后端内容版本、回滚和真实独立连接竞争的共同场景。

use memoswish_core::CoreError;
use memoswish_core::content::CardMutation;
use memoswish_core::ids::new_id;
use memoswish_core::repo::*;
use memoswish_protocol::{Card, CardDraft, examples};

pub(crate) async fn seed(repo: &impl Repository) -> (String, Card) {
    let tenant = new_id();
    let deck = examples::sample_deck();
    let card = examples::sample_card();
    repo.upsert_tenant(&TenantRecord {
        id: tenant.clone(),
        name: "CAS".into(),
        plan: "free".into(),
        created_at: card.created_at,
    })
    .await
    .unwrap();
    repo.insert_deck_with_cards(&tenant, &deck, std::slice::from_ref(&card)).await.unwrap();
    (tenant, card)
}

pub(crate) fn edit(card: &Card, expected_revision: Option<u32>, title: &str) -> CardMutation {
    let mut front = card.front.clone();
    front.title = title.into();
    CardMutation::Draft {
        id: card.id.clone(),
        draft: CardDraft {
            id: Some(card.id.clone()),
            expected_revision,
            deck_id: card.deck_id.clone(),
            template: None,
            language: Some(card.language.clone()),
            front,
            back: card.back.clone(),
            tags: card.tags.clone(),
            attributes: Default::default(),
            ducking: None,
            visual: None,
        },
    }
}

pub(crate) async fn suite(repo: &impl Repository, other: &impl Repository) {
    let (tenant, initial) = seed(repo).await;
    let barrier = tokio::sync::Barrier::new(2);
    let a = edit(&initial, Some(initial.revision), "A");
    let b = edit(&initial, Some(initial.revision), "B");
    let (left, right) = tokio::join!(
        async {
            barrier.wait().await;
            repo.mutate_cards(&tenant, &[a]).await
        },
        async {
            barrier.wait().await;
            other.mutate_cards(&tenant, &[b]).await
        },
    );
    let results = [left, right];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        matches!(results.iter().find(|r| r.is_err()).unwrap(), Err(CoreError::Conflict(message)) if message.contains("current revision 4"))
    );
    let current = repo.get_card(&tenant, &initial.id).await.unwrap().unwrap();
    assert_eq!(current.revision, initial.revision + 1);
    assert_eq!(&current, &results.into_iter().find_map(Result::ok).unwrap()[0]);
    assert!(current.tts.is_none());
    assert_eq!(current.bgm, initial.bgm);

    // 旧请求缺省版本时在当前快照合并，版本仍然严格递增。
    let blind = edit(&initial, None, "legacy");
    let latest = repo.mutate_cards(&tenant, &[blind]).await.unwrap().remove(0);
    assert_eq!(latest.revision, current.revision + 1);
    let fresh_id = new_id();
    let mut fresh = edit(&latest, None, "new");
    if let CardMutation::Draft { id, draft } = &mut fresh {
        *id = fresh_id.clone();
        draft.id = None;
    }
    let stale = edit(&initial, Some(initial.revision), "stale");
    assert!(matches!(repo.mutate_cards(&tenant, &[fresh.clone(), stale]).await, Err(CoreError::Conflict(_))));
    assert!(repo.get_card(&tenant, &fresh_id).await.unwrap().is_none());
    assert_eq!(repo.get_card(&tenant, &latest.id).await.unwrap().unwrap(), latest);
    let valid = edit(&latest, Some(latest.revision), "valid");
    assert!(matches!(repo.mutate_cards(&tenant, &[valid.clone(), valid.clone()]).await, Err(CoreError::Invalid(_))));
    assert!(matches!(repo.mutate_cards(&tenant, &[edit(&latest, Some(0), "zero")]).await, Err(CoreError::Invalid(_))));
    let mut invalid_create = fresh.clone();
    if let CardMutation::Draft { draft, .. } = &mut invalid_create {
        draft.expected_revision = Some(1);
    }
    assert!(matches!(repo.mutate_cards(&tenant, &[invalid_create]).await, Err(CoreError::Invalid(_))));

    let bgm = CardMutation::Bgm { id: latest.id.clone(), expected_revision: Some(latest.revision), binding: None };
    let (edit_result, bgm_result) = tokio::join!(async { repo.mutate_cards(&tenant, &[valid]).await }, async {
        other.mutate_cards(&tenant, &[bgm]).await
    });
    assert_eq!([edit_result.is_ok(), bgm_result.is_ok()].into_iter().filter(|v| *v).count(), 1);
    assert!(matches!(edit_result.err().or(bgm_result.err()), Some(CoreError::Conflict(_))));
    let before = repo.get_card(&tenant, &initial.id).await.unwrap().unwrap();
    let bindings = [
        CardMutation::Bgm { id: before.id.clone(), expected_revision: Some(before.revision), binding: None },
        CardMutation::Bgm { id: new_id(), expected_revision: None, binding: None },
    ];
    assert!(matches!(repo.mutate_cards(&tenant, &bindings).await, Err(CoreError::NotFound(_))));
    assert_eq!(repo.get_card(&tenant, &before.id).await.unwrap().unwrap(), before);

    // 同 ID 的其他租户不泄露当前版本，不读取或修改目标。
    let (other_tenant, _) = seed(repo).await;
    repo.delete_card(&other_tenant, &before.id).await.unwrap();
    assert!(matches!(
        repo.mutate_cards(&other_tenant, &[edit(&before, Some(before.revision), "foreign")]).await,
        Err(CoreError::NotFound(_))
    ));
    assert!(!repo.delete_card_if_revision(&other_tenant, &before.id, Some(before.revision)).await.unwrap());
    assert!(matches!(repo.delete_card_if_revision(&tenant, &before.id, Some(1)).await, Err(CoreError::Conflict(_))));
    assert!(repo.delete_card_if_revision(&tenant, &before.id, Some(before.revision)).await.unwrap());
    assert!(matches!(repo.mutate_cards(&tenant, &[edit(&before, None, "replay")]).await, Err(CoreError::NotFound(_))));
    assert!(repo.get_card(&tenant, &before.id).await.unwrap().is_none());

    // 卡组删除与新卡创建或移卡按同一父锁排序，无晚到孤儿。
    for moving in [false, true] {
        let (tenant, card) = seed(repo).await;
        let mut target = examples::sample_deck();
        target.id = new_id();
        repo.insert_deck(&tenant, &target).await.unwrap();
        let mut change = edit(&card, Some(card.revision), "race");
        let target_id = if moving { card.id.clone() } else { new_id() };
        if let CardMutation::Draft { id, draft } = &mut change {
            *id = target_id.clone();
            draft.deck_id = target.id.clone();
            if !moving {
                draft.id = None;
                draft.expected_revision = None;
            }
        }
        let (write, deleted) =
            tokio::join!(async { repo.mutate_cards(&tenant, &[change]).await }, other.delete_deck(&tenant, &target.id));
        assert!(deleted.unwrap());
        if let Err(error) = write {
            assert!(matches!(error, CoreError::NotFound(_)));
        }
        let remaining = repo.get_card(&tenant, &target_id).await.unwrap();
        assert!(remaining.is_none_or(|c| c.deck_id != target.id));
    }

    // 库曲目的共享与私有作用域独立，显式版本不能借共享行创建私有覆盖。
    let track = examples::sample_bgm_track();
    let private = repo.save_bgm(Some(&tenant), &track, None).await.unwrap();
    let mut changed = private.clone();
    changed.title = "new metadata".into();
    let (a, b) = tokio::join!(
        repo.save_bgm(Some(&tenant), &changed, Some(private.revision)),
        other.save_bgm(Some(&tenant), &track, Some(private.revision))
    );
    assert_eq!([a.is_ok(), b.is_ok()].into_iter().filter(|v| *v).count(), 1);
    assert!(matches!(a.err().or(b.err()), Some(CoreError::Conflict(_))));
    let shared = repo.save_bgm(None, &track, None).await.unwrap();
    assert!(matches!(
        repo.save_bgm(Some(&other_tenant), &shared, Some(shared.revision)).await,
        Err(CoreError::NotFound(_))
    ));
    assert_eq!(repo.get_bgm(&other_tenant, &track.id).await.unwrap().unwrap(), shared);
    assert_eq!(repo.get_bgm(&tenant, &track.id).await.unwrap().unwrap().revision, private.revision + 1);
}

macro_rules! content_tests {
    ($repo:ident, $pool:ty, $migrations:literal, $fail:literal, $drop:literal, $report:path) => {
        async fn s14_data_snapshot(pool: &$pool) -> Vec<Vec<Vec<Option<String>>>> {
            let extra = [
                ("background_jobs", "tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,state,attempts,max_attempts,available_at_ms,lease_until_ms,worker,token,result,error"),
                ("quota_operations", "tenant_id,operation_id,metric,period,amount,state"),
                ("memory_states", "tenant_id,user_id,card_id,projection_version"),
                ("feedback_events", "tenant_id,user_id,event_id,payload_hash,application_provenance"),
                ("tenant_memberships", "tenant_id,user_id,role,generation"),
                ("asset_upload_intents", "tenant_id,id,asset_id,account_generation,published_attempt"),
                ("asset_records", "tenant_id,id,mime,size,sha256"),
                ("asset_upload_attempts", "tenant_id,id,intent_id,store_id,object_key,claim_token,outcome,version_kind,version_id"),
                ("feed_page_receipts", "tenant_id,user_id,session_id,issuance_key,revision,context,page"),
            ];
            let mut out = Vec::new();
            for (table, columns) in crate::foundation_conformance::SNAPSHOTS.iter().chain(extra.iter()) {
                let table = if *table == "users" { "user_profiles" } else { table };
                let projection = columns.split(',').map(|c| format!("CAST({c} AS TEXT)")).collect::<Vec<_>>().join(",");
                // S19 新增的擦除工作独立验收；此快照仍逐字段保护迁移前的原工作。
                let scope=if table=="background_jobs" {"AND kind<>'erasure'"}else{""};
                let rows = sqlx::query(&format!("SELECT {projection} FROM {table} WHERE 1=1 {scope} ORDER BY {projection}"))
                    .fetch_all(pool).await.unwrap();
                out.push(rows.iter().map(|r| (0..columns.split(',').count()).map(|i| r.get(i)).collect()).collect());
            }
            out
        }

        async fn s14_upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 1).run(pool).await.unwrap();
            // 缺租户孤儿在早期无 guard 的 schema 中产生，不能用新 guard 拒绝写入代替升级回归。
            sqlx::query("INSERT INTO decks VALUES('historic-orphan','missing','Orphan','','en','[]','2026-11-01T00:00:00Z')").execute(pool).await.unwrap();
            crate::foundation_conformance::through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(crate::foundation_conformance::LEGACY_DATA).execute(pool).await.unwrap();
            crate::foundation_conformance::through(&full, 18).run(pool).await.unwrap();
            let invalid=s14_data_snapshot(pool).await;
            let report=$report(pool).await.unwrap();
            assert_eq!(report.iter().find(|r|r.category=="decks_missing_tenant").unwrap().row_count,1);
            let error=full.run(pool).await.unwrap_err().to_string();
            assert!(error.contains("content-orphan-report"),"{error}");
            assert_eq!(s14_data_snapshot(pool).await,invalid);
            // 仅删除本测试故意构造的孤儿；生产修复必须有独立归属证据。
            sqlx::query("DELETE FROM decks WHERE id='historic-orphan'").execute(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','s14-job','synthesis','s14-job','{}','account',7,3,100); INSERT INTO quota_operations VALUES('foundation','s14-job','tts_chars','2026-11',17,'reserved');").execute(pool).await.unwrap();
            // 旧正文有未知字段仍按原字节复制；已归档历史转为墓碑而不删除。
            sqlx::query("INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures) VALUES('foundation','account','archived',1,2,0,0,1)").execute(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO asset_records VALUES('foundation','s14-asset','audio/wav',4,'0000000000000000000000000000000000000000000000000000000000000000'); INSERT INTO asset_upload_intents VALUES('foundation','s14-job','s14-asset',7,NULL); INSERT INTO asset_upload_attempts VALUES('foundation','s14-attempt','s14-job','store','tenants/foundation/s14-asset','claim','uncertain','unknown',NULL);").execute(pool).await.unwrap();
            let old_repo=$repo { observer: memoswish_core::observability::noop(), pool:pool.clone(), learning_gate:None, content_gate:None, feed_gate:None, lifecycle_gate:None };
            let (event,memory)=crate::learning_conformance::seed(&old_repo).await;
            // 当前接受命令要求完整 S12 schema；旧版本夹具通过兼容插入构造。
            assert!(old_repo.insert_feedback(&event).await.unwrap());
            old_repo.upsert_memory(&memory).await.unwrap();
            // 旧版删除没有反馈的卡片后，仅 S11 回执保存其身份和正文。
            let p = crate::feed_issuance_conformance::seed(&old_repo).await;
            let request = crate::feed_issuance_conformance::first();
            // 旧 schema 夹具只构造当时的页与会话，不能调用依赖未来控制表的当前发卡命令。
            let mut page = memoswish_protocol::examples::sample_feed_page();
            page.session_id=request.new_session_id.clone();page.items.truncate(1);page.items[0].slot=0;
            page.generated_at=request.now;page.prefetch.entries.clear();
            page.next_cursor=format!("fp_{}",memoswish_core::ids::new_id());
            page.mode=None;page.policy_version=None;
            for item in &mut page.items {item.delivery_id=None;}
            let successor=memoswish_core::repo::FeedSession {id:page.session_id.clone(),tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),next_slot:1,recent_card_ids:page.items.iter().map(|item|item.card.id.clone()).collect(),created_at:request.now,updated_at:request.now};
            old_repo.save_session(&successor).await.unwrap();
            let context = serde_json::to_string(&(&request.query.deck_id, request.query.limit)).unwrap();
            sqlx::query("UPDATE feed_sessions SET first_request_id=$1,issuance_context=$2,issuance_revision=1,issuance_cursor=$3,expires_at_ms=$4 WHERE tenant_id=$5 AND user_id=$6 AND id=$7")
                .bind(&request.query.request_id).bind(&context).bind(&page.next_cursor)
                .bind(request.now.timestamp_millis()+crate::feed_issuance::SESSION_LIFETIME_MS)
                .bind(&p.tenant_id).bind(&p.user_id).bind(&page.session_id).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO feed_page_receipts(tenant_id,user_id,session_id,issuance_key,revision,context,page) VALUES($1,$2,$3,$4,1,$5,$6)")
                .bind(&p.tenant_id).bind(&p.user_id).bind(&page.session_id)
                .bind(format!("r:{}", request.query.request_id.as_ref().unwrap())).bind(&context)
                .bind(serde_json::to_string(&page).unwrap()).execute(pool).await.unwrap();
            let deleted = &page.items[0].card;
            assert!(old_repo.delete_card(&p.tenant_id, &deleted.id).await.unwrap());
            assert!(old_repo.get_memory(&p.tenant_id, &p.user_id, &deleted.id).await.unwrap().is_none());
            let baseline = s14_data_snapshot(pool).await;
            let mut broken = crate::foundation_conformance::through(&full, 19);
            let index = broken.migrations.len()-1;
            let version = broken.migrations[index].version;
            assert_eq!(version, 19);
            let sql = format!("{}\nSELECT * FROM s14_injected_failure;", broken.migrations[index].sql);
            broken.migrations.to_mut()[index] = sqlx::migrate::Migration::new(version, "injected failure".into(), sqlx::migrate::MigrationType::Simple, sql.into(), false);
            assert!(broken.run(pool).await.is_err());
            assert_eq!(s14_data_snapshot(pool).await, baseline);
            assert!(sqlx::query("SELECT * FROM deleted_card_ids").execute(pool).await.is_err());
            let latest: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(latest, 18);
            // 两种不明确归属分别阻止升级，失败后原表、历史和版本记录均保留。
            {
                sqlx::query("UPDATE cards SET deck_id='missing' WHERE tenant_id='foundation'").execute(pool).await.unwrap();
                let invalid = s14_data_snapshot(pool).await;
                let report = $report(pool).await.unwrap();
                assert!(report.iter().any(|r| (r.category=="decks_missing_tenant" || r.category=="cards_missing_owned_deck") && r.row_count>0));
                assert_eq!(s14_data_snapshot(pool).await, invalid);
                let error = full.run(pool).await.unwrap_err().to_string();
                assert!(error.contains("content-orphan-report"), "{error}");
                assert_eq!(s14_data_snapshot(pool).await, invalid);
                sqlx::raw_sql("UPDATE cards SET deck_id='deck' WHERE tenant_id='foundation';").execute(pool).await.unwrap();
            }
            full.run(pool).await.unwrap();
            assert_eq!(s14_data_snapshot(pool).await, baseline);
            full.run(pool).await.unwrap();
            assert_eq!(s14_data_snapshot(pool).await, baseline);
            let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id='foundation' AND card_id='archived'").fetch_one(pool).await.unwrap();
            assert_eq!(archived,1);
            let tombstone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1 AND card_id=$2")
                .bind(&p.tenant_id).bind(&deleted.id).fetch_one(pool).await.unwrap();
            assert_eq!(tombstone, 1);
            assert!(old_repo.insert_card(&p.tenant_id, deleted).await.is_err());
            assert_eq!(crate::feed_issuance_conformance::committed(old_repo.feed_issuance(&p, &request, None).await.unwrap()), page);
        }

        async fn s14_ownership_and_retention(repo: &$repo) {
            use memoswish_core::identity::IdentityRepo;
            use memoswish_core::repo::LearningEventOutcome::*;
            let (rec, state) = crate::learning_conformance::seed(repo).await;
            let (peer, _) = crate::learning_conformance::seed(repo).await;
            let tenant = &rec.tenant_id;
            let card = repo.get_card(tenant, &state.card_id).await.unwrap().unwrap();
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Applied);
            let mut legacy = rec.clone(); legacy.event.event_id.push_str("legacy");
            assert!(repo.insert_feedback(&legacy).await.unwrap());
            // 同租户多个学习者、多个卡片，以及其他卡组的零复习曝光均须独立保留。
            let mut learner = repo.get_user(tenant, &rec.user_id).await.unwrap().unwrap();
            learner.id = memoswish_core::ids::new_id(); learner.email = format!("{}@example.com",learner.id);
            repo.insert_user(&learner).await.unwrap();
            let mut second_state = state.clone(); second_state.user_id=learner.id.clone();
            repo.upsert_memory(&second_state).await.unwrap();
            let mut second_card=card.clone(); second_card.id=memoswish_core::ids::new_id();
            repo.insert_card(tenant,&second_card).await.unwrap();
            let mut second_memory=state.clone(); second_memory.card_id=second_card.id.clone(); second_memory.reps=0;
            repo.upsert_memory(&second_memory).await.unwrap();
            let mut surviving_deck=memoswish_protocol::examples::sample_deck(); surviving_deck.id=memoswish_core::ids::new_id();
            repo.insert_deck(tenant,&surviving_deck).await.unwrap();
            let mut survivor=card.clone(); survivor.id=memoswish_core::ids::new_id(); survivor.deck_id=surviving_deck.id.clone();
            repo.insert_card(tenant,&survivor).await.unwrap();
            let mut surviving_memory=state.clone(); surviving_memory.card_id=survivor.id.clone(); surviving_memory.reps=0;
            repo.upsert_memory(&surviving_memory).await.unwrap();
            // 原生 INSERT/UPDATE 不能绕过复合父归属；跨租户同 ID 只属于各自父对象。
            for query in [
                "UPDATE cards SET deck_id='absent' WHERE tenant_id=$1 AND id=$2",
                "UPDATE cards SET tenant_id='absent' WHERE tenant_id=$1 AND id=$2",
                "UPDATE cards SET id='renamed' WHERE tenant_id=$1 AND id=$2",
                "INSERT INTO cards SELECT 'bad-parent',tenant_id,'absent',template,revision,body,created_at,updated_at FROM cards WHERE tenant_id=$1 AND id=$2",
            ] { assert!(sqlx::query(query).bind(tenant).bind(&card.id).execute(repo.pool()).await.is_err(),"{query}"); }
            let mut foreign_deck=surviving_deck.clone(); foreign_deck.id=memoswish_core::ids::new_id();
            repo.insert_deck(&peer.tenant_id,&foreign_deck).await.unwrap();
            assert!(sqlx::query("UPDATE cards SET deck_id=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&card.id).bind(&foreign_deck.id).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("INSERT INTO cards SELECT 'foreign-parent',tenant_id,$3,template,revision,body,created_at,updated_at FROM cards WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&card.id).bind(&foreign_deck.id).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("UPDATE decks SET tenant_id='absent' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&card.deck_id).execute(repo.pool()).await.is_err());
            assert!(repo.insert_deck("absent", &surviving_deck).await.is_err());
            assert_eq!(repo.get_card(tenant,&card.id).await.unwrap().unwrap(),card);
            sqlx::query("INSERT INTO asset_records(tenant_id,id,mime,size,sha256) VALUES($1,'s14-retained','audio/wav',4,'0000000000000000000000000000000000000000000000000000000000000000')").bind(tenant).execute(repo.pool()).await.unwrap();
            let saved=crate::learning_conformance::snapshot(repo,&rec).await;
            let before=repo.account_export(tenant,&rec.user_id,false).await.unwrap();
            // 取消真实删除事务，墓碑与内容删除必须一起回滚。
            let mut tx=repo.pool().begin().await.unwrap();
            sqlx::query("DELETE FROM cards WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&card.id).execute(&mut *tx).await.unwrap();
            tx.rollback().await.unwrap();
            assert_eq!(repo.get_card(tenant,&card.id).await.unwrap().unwrap(),card);
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1 AND card_id=$2").bind(tenant).bind(&card.id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count,0);
            assert!(repo.delete_card(tenant,&card.id).await.unwrap());
            assert_eq!(crate::learning_conformance::snapshot(repo,&rec).await,saved);
            let after=repo.account_export(tenant,&rec.user_id,false).await.unwrap();
            for table in ["memory_states","feedback_events"] { assert_eq!(before[table],after[table],"{table}"); }
            assert_eq!(repo.try_apply_learning_event(&rec,None,&state).await.unwrap(),Duplicate);
            assert_eq!(repo.try_apply_learning_event(&legacy,None,&state).await.unwrap(),Duplicate);
            legacy.event.double_tapped=!legacy.event.double_tapped;
            assert_eq!(repo.try_apply_learning_event(&legacy,None,&state).await.unwrap(),PayloadConflict);
            let mut fresh=rec.clone(); fresh.event.event_id.push_str("fresh");
            assert_eq!(repo.try_apply_learning_event(&fresh,None,&state).await.unwrap(),MissingCard);
            assert!(!repo.list_memory(tenant,&rec.user_id).await.unwrap().iter().any(|m|m.card_id==card.id));
            assert!(repo.insert_card(tenant,&card).await.is_err());
            // 严格整包导入也不能复活墓碑，失败不能留下新 deck。
            let mut retry_deck=surviving_deck.clone(); retry_deck.id=memoswish_core::ids::new_id();
            let mut retry_card=card.clone();retry_card.deck_id=retry_deck.id.clone();
            assert!(repo.insert_deck_with_cards(tenant,&retry_deck,&[retry_card]).await.is_err());
            assert!(repo.get_deck(tenant,&retry_deck.id).await.unwrap().is_none());
            assert!(matches!(repo.mutate_cards(tenant,&[crate::content_conformance::edit(&card,None,"restore")]).await,Err(CoreError::NotFound(_))));
            // 使用数据库级级联删除，不能只依赖仓储主动删子表。
            sqlx::query("DELETE FROM decks WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&card.deck_id).execute(repo.pool()).await.unwrap();
            assert!(repo.get_card(tenant,&second_card.id).await.unwrap().is_none());
            assert_eq!(repo.get_memory(tenant,&learner.id,&card.id).await.unwrap(),Some(second_state));
            assert_eq!(repo.list_memory(tenant,&rec.user_id).await.unwrap(),vec![surviving_memory]);
            assert!(repo.list_memory(tenant,&learner.id).await.unwrap().is_empty());
            repo.insert_deck(tenant,&memoswish_protocol::examples::sample_deck()).await.unwrap();
            assert!(repo.insert_card(tenant,&second_card).await.is_err());
            let mut restored=card.clone(); restored.id=memoswish_core::ids::new_id();
            repo.insert_card(tenant,&restored).await.unwrap();
            assert!(repo.get_memory(tenant,&rec.user_id,&restored.id).await.unwrap().is_none());
            assert!(repo.get_card(&peer.tenant_id,&card.id).await.unwrap().is_some());
            // 成员擦除清掉本人归档历史，保留同租户另一学习者；owner 擦除清掉剩余历史。
            assert!(repo.feed_summary(tenant,&rec.user_id,None).await.unwrap().total_exposures > 0);
            repo.account_erase(tenant,&rec.user_id,false).await.unwrap();
            assert_eq!(repo.feed_summary(tenant,&rec.user_id,None).await.unwrap().total_exposures,0);
            assert!(repo.starred_feed_cards(tenant,&rec.user_id,None).await.unwrap().is_empty());
            assert!(repo.get_memory(tenant,&rec.user_id,&card.id).await.unwrap().is_none());
            assert!(repo.get_memory(tenant,&learner.id,&card.id).await.unwrap().is_some());
            sqlx::query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2").bind(tenant).bind(&learner.id).execute(repo.pool()).await.unwrap();
            repo.account_erase(tenant,&learner.id,true).await.unwrap();
            assert_eq!(repo.feed_summary(tenant,&learner.id,None).await.unwrap().total_cards,0);
            assert!(repo.hydrate_feed_cards(tenant,None,&[restored.id.clone()]).await.unwrap().is_empty());
            let mut candidates=Vec::new();
            repo.visit_feed_metadata(tenant,&learner.id,None,&mut |card|{candidates.push(card);Ok(())}).await.unwrap();
            assert!(candidates.is_empty());
            assert!(repo.feed_summary(&peer.tenant_id,&peer.user_id,None).await.unwrap().total_cards>0);
            let assets:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_records WHERE tenant_id=$1 AND id='s14-retained'").bind(tenant).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(assets,1);
            assert!(repo.get_memory(tenant,&learner.id,&card.id).await.unwrap().is_none());
            assert!(repo.get_card(&peer.tenant_id,&card.id).await.unwrap().is_some());
        }

        async fn s14_delete_rollback_and_orderings(repo: &$repo) {
            use memoswish_core::repo::LearningEventOutcome::*;
            // 外键注入真实删除失败：卡片、整组删除和墓碑必须同事务回滚。
            let (tenant,card)=crate::content_conformance::seed(repo).await;
            sqlx::query("CREATE TABLE s14_delete_dependency(tenant_id TEXT,card_id TEXT,FOREIGN KEY(tenant_id,card_id) REFERENCES cards(tenant_id,id) ON DELETE RESTRICT)").execute(repo.pool()).await.unwrap();
            sqlx::query("INSERT INTO s14_delete_dependency VALUES($1,$2)").bind(&tenant).bind(&card.id).execute(repo.pool()).await.unwrap();
            assert!(repo.delete_card(&tenant,&card.id).await.is_err());
            assert!(repo.delete_deck(&tenant,&card.deck_id).await.is_err());
            assert_eq!(repo.get_card(&tenant,&card.id).await.unwrap(),Some(card.clone()));
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1").bind(&tenant).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count,0);
            sqlx::query("DROP TABLE s14_delete_dependency").execute(repo.pool()).await.unwrap();
            for whole_deck in [false,true] {
                let (rec,state)=crate::learning_conformance::seed(repo).await;
                let original=repo.get_card(&rec.tenant_id,&rec.event.card_id).await.unwrap().unwrap();
                let gate=crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                let mut paused=repo.clone(); paused.content_gate=Some(gate.clone());
                let (tid,cid,did)=(rec.tenant_id.clone(),original.id.clone(),original.deck_id.clone());
                let deleting=tokio::spawn(async move {
                    if whole_deck {paused.delete_deck(&tid,&did).await} else {paused.delete_card(&tid,&cid).await}
                });
                gate.reached.notified().await;
                assert_eq!(repo.get_card(&rec.tenant_id,&original.id).await.unwrap(),Some(original.clone()));
                deleting.abort(); assert!(deleting.await.unwrap_err().is_cancelled());
                assert_eq!(repo.get_card(&rec.tenant_id,&original.id).await.unwrap(),Some(original.clone()));
                // 删除持锁后启动反馈；实际观察数据库等待再提交，反馈不能留下回执或投影。
                let mut paused=repo.clone(); paused.content_gate=Some(gate.clone());
                let (tid,cid,did)=(rec.tenant_id.clone(),original.id.clone(),original.deck_id.clone());
                let deleting=tokio::spawn(async move {
                    if whole_deck {paused.delete_deck(&tid,&did).await} else {paused.delete_card(&tid,&cid).await}
                });
                gate.reached.notified().await;
                let copy=repo.clone(); let (record,successor)=(rec.clone(),state.clone());
                let feedback=tokio::spawn(async move {copy.try_apply_learning_event(&record,None,&successor).await});
                s13_observe_content_wait(repo).await;
                assert!(!feedback.is_finished()); gate.resume.add_permits(1);
                assert!(deleting.await.unwrap().unwrap());
                assert_eq!(feedback.await.unwrap().unwrap(),MissingCard);
                assert!(repo.get_versioned_memory(&rec.tenant_id,&rec.user_id,&original.id).await.unwrap().is_none());
                let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM feedback_events WHERE tenant_id=$1").bind(&rec.tenant_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(count,0);
            }
            // 创建/移卡与删除目标 deck，两种持锁顺序都在独立连接上确定执行。
            for moving in [false,true] { for delete_first in [false,true] {
                let (tenant,card)=crate::content_conformance::seed(repo).await;
                let mut target=memoswish_protocol::examples::sample_deck();target.id=memoswish_core::ids::new_id();
                repo.insert_deck(&tenant,&target).await.unwrap();
                let mut change=crate::content_conformance::edit(&card,Some(card.revision),"ordered");
                if let memoswish_core::content::CardMutation::Draft{id,draft}=&mut change {
                    draft.deck_id=target.id.clone();
                    if !moving { *id=memoswish_core::ids::new_id();draft.id=None;draft.expected_revision=None; }
                }
                let changed_id=change.id().to_string();
                let gate=crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                let mut paused=repo.clone();paused.content_gate=Some(gate.clone());
                let (tid,did,mutation)=(tenant.clone(),target.id.clone(),change.clone());
                let first=tokio::spawn(async move {
                    if delete_first { paused.delete_deck(&tid,&did).await.map(|_|()) }
                    else { paused.mutate_cards(&tid,&[mutation]).await.map(|_|()) }
                });
                gate.reached.notified().await;
                let copy=repo.clone();let (tid,did)=(tenant.clone(),target.id.clone());
                let second=tokio::spawn(async move {
                    if delete_first {copy.mutate_cards(&tid,&[change]).await.map(|_|())}
                    else {copy.delete_deck(&tid,&did).await.map(|_|())}
                });
                s13_observe_content_wait(repo).await;
                assert!(!second.is_finished());gate.resume.add_permits(1);
                first.await.unwrap().unwrap();
                let result=second.await.unwrap();
                if delete_first {assert!(matches!(result,Err(CoreError::NotFound(_))));} else {result.unwrap();}
                assert!(repo.get_card(&tenant,&changed_id).await.unwrap().is_none_or(|c|c.deck_id!=target.id));
            }}
        }

        async fn s14_content_write_and_erasure(repo: &$repo) {
            use memoswish_core::identity::IdentityRepo;
            let (rec,_)=crate::learning_conformance::seed(repo).await;
            let (peer,_) = crate::learning_conformance::seed(repo).await;
            let card=repo.get_card(&rec.tenant_id,&rec.event.card_id).await.unwrap().unwrap();
            sqlx::query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2").bind(&rec.tenant_id).bind(&rec.user_id).execute(repo.pool()).await.unwrap();
            let gate=crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
            let mut paused=repo.clone();paused.content_gate=Some(gate.clone());
            let (tid,change)=(rec.tenant_id.clone(),crate::content_conformance::edit(&card,None,"write before erasure"));
            let write=tokio::spawn(async move{paused.mutate_cards(&tid,&[change]).await});
            gate.reached.notified().await;
            let copy=repo.clone();let (tid,uid)=(rec.tenant_id.clone(),rec.user_id.clone());
            let erase=tokio::spawn(async move{copy.account_erase(&tid,&uid,true).await});
            s13_observe_content_wait(repo).await;
            assert!(!erase.is_finished());gate.resume.add_permits(1);
            write.await.unwrap().unwrap();erase.await.unwrap().unwrap();
            assert!(repo.get_card(&rec.tenant_id,&card.id).await.unwrap().is_none());
            // 擦除先提交时，另一连接的迟到严格导入与普通写均不能重建租户内容。
            let other=repo.clone();
            assert!(other.insert_card(&rec.tenant_id,&card).await.is_err());
            assert!(other.insert_deck(&rec.tenant_id,&memoswish_protocol::examples::sample_deck()).await.is_err());
            assert!(other.mutate_cards(&rec.tenant_id,&[crate::content_conformance::edit(&card,None,"late")]).await.is_err());
            assert!(repo.get_card(&peer.tenant_id,&card.id).await.unwrap().is_some());
        }

        async fn s13_upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 12).run(pool).await.unwrap();
            let track = memoswish_protocol::examples::sample_bgm_track();
            let mut old = serde_json::to_value(&track).unwrap();
            old.as_object_mut().unwrap().remove("revision");
            sqlx::query("INSERT INTO bgm_tracks (tenant_id,id,body) VALUES ('', $1, $2)")
                .bind(&track.id)
                .bind(sqlx::types::Json(old))
                .execute(pool)
                .await
                .unwrap();
            full.run(pool).await.unwrap();
            let revision: i64 = sqlx::query_scalar("SELECT revision FROM bgm_tracks WHERE tenant_id='' AND id=$1")
                .bind(&track.id)
                .fetch_one(pool)
                .await
                .unwrap();
            let body: sqlx::types::Json<memoswish_protocol::BgmTrack> =
                sqlx::query_scalar("SELECT body FROM bgm_tracks WHERE tenant_id='' AND id=$1")
                    .bind(&track.id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(revision, 1);
            assert_eq!(body.0, track);
        }

        async fn s13_sql_failure_and_overflow(repo: &$repo) {
            use memoswish_core::content::CardMutation;
            let (tenant, card) = crate::content_conformance::seed(repo).await;
            let fresh_id = memoswish_core::ids::new_id();
            let mut fresh = crate::content_conformance::edit(&card, None, "new");
            if let CardMutation::Draft { id, draft } = &mut fresh {
                *id = fresh_id.clone();
                draft.id = None;
            }
            let failed = crate::content_conformance::edit(&card, Some(card.revision), "SQL_FAIL");
            sqlx::raw_sql($fail).execute(repo.pool()).await.unwrap();
            assert!(repo.mutate_cards(&tenant, &[fresh, failed]).await.is_err());
            assert!(repo.get_card(&tenant, &fresh_id).await.unwrap().is_none());
            assert_eq!(repo.get_card(&tenant, &card.id).await.unwrap().unwrap(), card);
            sqlx::raw_sql($drop).execute(repo.pool()).await.unwrap();
            let mut maximum = card.clone();
            maximum.id = memoswish_core::ids::new_id();
            maximum.revision = u32::MAX;
            repo.insert_card(&tenant, &maximum).await.unwrap();
            assert!(matches!(
                repo.mutate_cards(&tenant, &[crate::content_conformance::edit(&maximum, Some(u32::MAX), "overflow")])
                    .await,
                Err(CoreError::Conflict(_))
            ));
            assert_eq!(repo.get_card(&tenant, &maximum.id).await.unwrap().unwrap(), maximum);
            let mut track = memoswish_protocol::examples::sample_bgm_track();
            track.revision = u32::MAX;
            sqlx::query("INSERT INTO bgm_tracks(tenant_id,id,revision,body) VALUES($1,$2,$3,$4)")
                .bind(&tenant)
                .bind(&track.id)
                .bind(i64::from(u32::MAX))
                .bind(sqlx::types::Json(&track))
                .execute(repo.pool())
                .await
                .unwrap();
            assert!(matches!(repo.save_bgm(Some(&tenant), &track, Some(u32::MAX)).await, Err(CoreError::Conflict(_))));
            assert!(matches!(repo.save_bgm(Some(&tenant), &track, Some(0)).await, Err(CoreError::Invalid(_))));
            assert_eq!(repo.get_bgm(&tenant, &track.id).await.unwrap().unwrap(), track);
        }

        async fn s13_cancel_before_commit(repo: &$repo) {
            let (tenant, card) = crate::content_conformance::seed(repo).await;
            let change = crate::content_conformance::edit(&card, Some(card.revision), "cancelled");
            let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
            let mut paused = repo.clone();
            paused.content_gate = Some(gate.clone());
            let task_tenant = tenant.clone();
            let task_change = change.clone();
            let fresh_id = memoswish_core::ids::new_id();
            let mut fresh = crate::content_conformance::edit(&card, None, "created then cancelled");
            if let memoswish_core::content::CardMutation::Draft { id, draft } = &mut fresh {
                *id = fresh_id.clone();
                draft.id = None;
            }
            let task = tokio::spawn(async move { paused.mutate_cards(&task_tenant, &[task_change, fresh]).await });
            gate.reached.notified().await;
            assert_eq!(repo.get_card(&tenant, &card.id).await.unwrap().unwrap(), card);
            assert!(repo.get_card(&tenant, &fresh_id).await.unwrap().is_none());
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(repo.get_card(&tenant, &card.id).await.unwrap().unwrap(), card);
            assert!(repo.get_card(&tenant, &fresh_id).await.unwrap().is_none());
            let committed = repo.mutate_cards(&tenant, std::slice::from_ref(&change)).await.unwrap().remove(0);
            // 提交响应丢失后重送原前提只能冲突，不能再次覆盖。
            assert!(matches!(repo.mutate_cards(&tenant, &[change]).await, Err(CoreError::Conflict(_))));
            assert_eq!(repo.get_card(&tenant, &card.id).await.unwrap().unwrap(), committed);
        }

        async fn s13_overlapping_transactions(repo: &$repo) {
            let (tenant, card) = crate::content_conformance::seed(repo).await;
            let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
            let mut first_repo = repo.clone();
            first_repo.content_gate = Some(gate.clone());
            let first_tenant = tenant.clone();
            let first_change = crate::content_conformance::edit(&card, Some(card.revision), "winner");
            let first = tokio::spawn(async move { first_repo.mutate_cards(&first_tenant, &[first_change]).await });
            gate.reached.notified().await;
            let second_repo = repo.clone();
            let second_tenant = tenant.clone();
            let second_change = crate::content_conformance::edit(&card, Some(card.revision), "loser");
            let started = std::sync::Arc::new(tokio::sync::Notify::new());
            let notify = started.clone();
            let second = tokio::spawn(async move {
                notify.notify_one();
                second_repo.mutate_cards(&second_tenant, &[second_change]).await
            });
            started.notified().await;
            s13_observe_content_wait(repo).await;
            assert!(!second.is_finished());
            gate.resume.add_permits(1);
            let winner = first.await.unwrap().unwrap().remove(0);
            assert!(matches!(second.await.unwrap(), Err(CoreError::Conflict(_))));
            assert_eq!(repo.get_card(&tenant, &card.id).await.unwrap().unwrap(), winner);
        }
    };
}
pub(crate) use content_tests;
