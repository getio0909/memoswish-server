//! S17 共享双库验收；每个状态用持久行和实际内容证明。
use super::*;
use memoswish_protocol::tts::TtsDisposition;

pub(super) async fn targets(repo: &impl Repository, p: &Principal, count: usize) -> Vec<SpeechSubmissionTarget> {
    let mut deck = memoswish_protocol::examples::sample_deck();
    deck.id = memoswish_core::ids::new_id();
    let cards: Vec<_> = (0..count)
        .map(|_| {
            let mut card = memoswish_protocol::examples::sample_card();
            card.id = memoswish_core::ids::new_id();
            card.deck_id = deck.id.clone();
            card.tts = None;
            card
        })
        .collect();
    repo.insert_deck_with_cards(&p.tenant_id, &deck, &cards).await.unwrap();
    cards.into_iter().map(|c| SpeechSubmissionTarget { card_id: c.id, revision: c.revision, work: work() }).collect()
}

pub(super) async fn submissions(repo: &impl Repository, other: &impl Repository) {
    let p = seed(repo).await;
    let targets = targets(repo, &p, 2).await;
    let hash = "a".repeat(64);
    let barrier = tokio::sync::Barrier::new(2);
    let (a, b) = tokio::join!(
        async {
            barrier.wait().await;
            repo.submit_speech(&p, "atomic", &hash, &targets, Some(3)).await
        },
        async {
            barrier.wait().await;
            other.submit_speech(&p, "atomic", &hash, &targets, Some(3)).await
        },
    );
    let accepted = a.unwrap();
    assert_eq!(accepted, b.unwrap());
    assert!(!accepted.complete);
    assert_ne!(accepted.items[0].item_id, accepted.items[1].item_id);
    let first = repo.speech_request(&p.tenant_id, &accepted.items[0].item_id).await.unwrap();
    let second = repo.speech_request(&p.tenant_id, &accepted.items[1].item_id).await.unwrap();
    assert_eq!(first.synthesis_id, second.synthesis_id);
    assert!(matches!(
        repo.submit_speech(&p, "atomic", &"b".repeat(64), &targets, None).await,
        Err(CoreError::Conflict(_))
    ));
    assert!(matches!(repo.speech_submission(&p, "atomic", Some(&"b".repeat(64))).await, Err(CoreError::Conflict(_))));
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3, 0));
    let foreign = seed(repo).await;
    assert!(repo.speech_submission(&foreign, "atomic", None).await.unwrap().is_none());
    let mut peer = seed(repo).await;
    repo.membership_join(&p.tenant_id, &peer.user_id, Role::Editor).await.unwrap();
    peer.tenant_id = p.tenant_id.clone();
    peer.role = Role::Editor;
    assert!(repo.speech_submission(&peer, "atomic", None).await.unwrap().is_none());
    // 成员角色仍允许时，也不能借用新世代查看旧所有者回执。
    let stale = Principal { membership_generation: Some(1), ..p.clone() };
    assert!(repo.speech_submission(&stale, "atomic", None).await.is_err());
    materialize(repo, &p, &first).await;
    publish(repo, &p, &first).await;
    // 已发布结果不在 S16 合成队列内，独立挂载扫描仍必须找到它。
    assert!(
        !repo.pending_speech(None, 100).await.unwrap().contains(&(p.tenant_id.clone(), first.synthesis_id.clone()))
    );
    assert!(
        repo.pending_speech_attachments(Some((&p.tenant_id, "")), 100)
            .await
            .unwrap()
            .contains(&(p.tenant_id.clone(), first.id.clone()))
    );
    // 一个兄弟发生 CAS 冲突，不阻止另一个成功。
    let mut card = repo.get_card(&p.tenant_id, &targets[1].card_id).await.unwrap().unwrap();
    card.front.title = "Competing edit".into();
    repo.mutate_cards(&p.tenant_id, &[crate::content_conformance::edit(&card, Some(card.revision), "Competing edit")])
        .await
        .unwrap();
    let barrier = tokio::sync::Barrier::new(2);
    let (a, b) = tokio::join!(
        async {
            barrier.wait().await;
            repo.resolve_speech_attachment(&p.tenant_id, &first.id).await
        },
        async {
            barrier.wait().await;
            other.resolve_speech_attachment(&p.tenant_id, &first.id).await
        },
    );
    a.unwrap();
    b.unwrap();
    repo.resolve_speech_attachment(&p.tenant_id, &second.id).await.unwrap();
    let terminal = repo.speech_submission(&p, "atomic", None).await.unwrap().unwrap();
    assert!(terminal.complete);
    assert_eq!(terminal.items[0].receipt.as_ref().unwrap().disposition, TtsDisposition::Attached);
    assert_eq!(terminal.items[0].receipt.as_ref().unwrap().resulting_revision, Some(targets[0].revision + 1));
    assert_eq!(terminal.items[1].receipt.as_ref().unwrap().disposition, TtsDisposition::Conflict);
    assert!(terminal.items[1].receipt.as_ref().unwrap().resulting_revision.is_none());
    assert_eq!(
        repo.get_card(&p.tenant_id, &targets[0].card_id).await.unwrap().unwrap().revision,
        targets[0].revision + 1
    );
    assert_eq!(repo.get_card(&p.tenant_id, &targets[1].card_id).await.unwrap().unwrap().front.title, "Competing edit");
    // 删除后仍重放原始事实，不重读卡片、重新解析参数或重建删除 ID。
    repo.delete_card(&p.tenant_id, &targets[0].card_id).await.unwrap();
    assert_eq!(repo.submit_speech(&p, "atomic", &hash, &[], Some(0)).await.unwrap(), terminal);
    repo.resolve_speech_attachment(&p.tenant_id, &first.id).await.unwrap();
    assert_eq!(repo.speech_submission(&p, "atomic", None).await.unwrap().unwrap(), terminal);
    assert!(repo.get_card(&p.tenant_id, &targets[0].card_id).await.unwrap().is_none());
    assert_eq!(repo.get_usage(&p.tenant_id, "tts_chars", &period).await.unwrap(), 3);
}

pub(super) async fn deletion_and_atomic_validation(repo: &impl Repository) {
    let p = seed(repo).await;
    let hash = "a".repeat(64);
    let mut ts = targets(repo, &p, 2).await;
    ts[1].work.request.voice = "distinct".into();
    assert!(matches!(repo.submit_speech(&p, "quota", &hash, &ts, Some(3)).await, Err(CoreError::QuotaExceeded(_))));
    assert!(repo.speech_submission(&p, "quota", None).await.unwrap().is_none());
    assert_eq!(
        repo.held_speech_usage(&p.tenant_id, &chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),
        (0, 0)
    );
    for bad in ["zero", "duplicate", "missing", "work"] {
        let mut invalid: Vec<_> = ts
            .iter()
            .map(|t| SpeechSubmissionTarget { card_id: t.card_id.clone(), revision: t.revision, work: t.work.clone() })
            .collect();
        match bad {
            "zero" => invalid[1].revision = 0,
            "duplicate" => invalid[1].card_id = invalid[0].card_id.clone(),
            "missing" => invalid[1].card_id = "missing-card".into(),
            _ => invalid[1].work.request.speed = f32::NAN,
        }
        assert!(repo.submit_speech(&p, bad, &hash, &invalid, None).await.is_err());
        assert!(repo.speech_submission(&p, bad, None).await.unwrap().is_none());
    }
    for deck_delete in [false, true] {
        let mut ts = targets(repo, &p, 1).await;
        ts[0].work.request.voice = if deck_delete { "deck" } else { "card" }.into();
        let id = if deck_delete { "delete-deck" } else { "delete-card" };
        let accepted = repo.submit_speech(&p, id, &hash, &ts, None).await.unwrap();
        let r = repo.speech_request(&p.tenant_id, &accepted.items[0].item_id).await.unwrap();
        materialize(repo, &p, &r).await;
        publish(repo, &p, &r).await;
        if deck_delete {
            let card = repo.get_card(&p.tenant_id, &ts[0].card_id).await.unwrap().unwrap();
            repo.delete_deck(&p.tenant_id, &card.deck_id).await.unwrap();
        } else {
            repo.delete_card(&p.tenant_id, &ts[0].card_id).await.unwrap();
        }
        repo.resolve_speech_attachment(&p.tenant_id, &r.id).await.unwrap();
        let result = repo.speech_submission(&p, id, None).await.unwrap().unwrap();
        assert!(result.complete);
        assert_eq!(result.items[0].receipt.as_ref().unwrap().disposition, TtsDisposition::NotFound);
    }
}

pub(super) async fn restart_prepare(repo: &impl Repository) -> (Principal, String, String) {
    let p = seed(repo).await;
    let ts = targets(repo, &p, 1).await;
    let accepted = repo.submit_speech(&p, "restart", &"a".repeat(64), &ts, None).await.unwrap();
    let r = repo.speech_request(&p.tenant_id, &accepted.items[0].item_id).await.unwrap();
    materialize(repo, &p, &r).await;
    publish(repo, &p, &r).await;
    (p, accepted.items[0].item_id.clone(), ts[0].card_id.clone())
}
pub(super) async fn restart_finish(repo: &impl Repository, state: (Principal, String, String)) {
    let (p, item, card) = state;
    assert!(
        repo.pending_speech_attachments(Some((&p.tenant_id, "")), 100)
            .await
            .unwrap()
            .contains(&(p.tenant_id.clone(), item.clone()))
    );
    repo.resolve_speech_attachment(&p.tenant_id, &item).await.unwrap();
    let status = repo.speech_submission(&p, "restart", None).await.unwrap().unwrap();
    assert!(status.complete);
    assert_eq!(status.items[0].receipt.as_ref().unwrap().disposition, TtsDisposition::Attached);
    assert_eq!(
        repo.get_card(&p.tenant_id, &card).await.unwrap().unwrap().revision,
        status.items[0].receipt.as_ref().unwrap().resulting_revision.unwrap()
    );
}

macro_rules! faults {
    ($repo:ty,$sqlite:literal) => {
        async fn s17_faults(repo:&$repo) {
            use sqlx::Row;
            for table in ["receipt","reference"] {
                let (p,item,card)=submissions::restart_prepare(repo).await;
                let trigger=if table=="receipt" {
                    if $sqlite {"CREATE TRIGGER s17_fail BEFORE UPDATE OF receipt ON tts_submission_items BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;"} else {"CREATE FUNCTION s17_fail_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SECRET_SENTINEL'; END $$; CREATE TRIGGER s17_fail BEFORE UPDATE OF receipt ON tts_submission_items FOR EACH ROW EXECUTE FUNCTION s17_fail_fn();"}
                } else if $sqlite {"CREATE TRIGGER s17_fail BEFORE INSERT ON asset_references WHEN NEW.slot='tts_card' BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;"} else {"CREATE FUNCTION s17_fail_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.slot='tts_card' THEN RAISE EXCEPTION 'SECRET_SENTINEL'; END IF; RETURN NEW; END $$; CREATE TRIGGER s17_fail BEFORE INSERT ON asset_references FOR EACH ROW EXECUTE FUNCTION s17_fail_fn();"};
                sqlx::raw_sql(trigger).execute(repo.pool()).await.unwrap();
                let before=repo.get_card(&p.tenant_id,&card).await.unwrap().unwrap();
                let e=repo.resolve_speech_attachment(&p.tenant_id,&item).await.unwrap_err();
                assert!(!format!("{e} {e:?}").contains("SECRET_SENTINEL"));
                assert_eq!(repo.get_card(&p.tenant_id,&card).await.unwrap().unwrap(),before);
                assert!(!repo.speech_submission(&p,"restart",None).await.unwrap().unwrap().complete);
                assert_eq!(repo.speech_request(&p.tenant_id,&item).await.unwrap().outcome,"published");
                let refs:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id=$1 AND owner_id=$2 AND slot='tts_card'").bind(&p.tenant_id).bind(&card).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(refs,0);
                let drop=if $sqlite {"DROP TRIGGER s17_fail;"}else if table=="receipt" {"DROP TRIGGER s17_fail ON tts_submission_items; DROP FUNCTION s17_fail_fn();"}else{"DROP TRIGGER s17_fail ON asset_references; DROP FUNCTION s17_fail_fn();"};
                sqlx::raw_sql(drop).execute(repo.pool()).await.unwrap();
                repo.resolve_speech_attachment(&p.tenant_id,&item).await.unwrap();
                assert!(repo.speech_submission(&p,"restart",None).await.unwrap().unwrap().complete);
                let immutable=repo.speech_submission(&p,"restart",None).await.unwrap().unwrap();
                // 生命周期撤销不能改写已提交的终态事实。
                repo.membership_remove(&p.tenant_id,&p.user_id).await.unwrap();
                repo.resolve_speech_attachment(&p.tenant_id,&item).await.unwrap();
                let raw=sqlx::query("SELECT receipt FROM tts_submission_items WHERE tenant_id=$1 AND item_id=$2").bind(&p.tenant_id).bind(&item).fetch_one(repo.pool()).await.unwrap();
                let receipt:memoswish_protocol::TtsAttachmentReceipt=serde_json::from_str(&raw.get::<String,_>("receipt")).unwrap();
                assert_eq!(Some(receipt),immutable.items[0].receipt);
                assert!(repo.speech_submission(&p,"restart",None).await.is_err());
            }
            // 超过一页，早期 SQL 失败不影响后续已发布目标；游标严格向前。
            let p=seed(repo).await;
            let ts=submissions::targets(repo,&p,100).await;
            repo.submit_speech(&p,"page-a",&"a".repeat(64),&ts,None).await.unwrap();
            let ts=submissions::targets(repo,&p,2).await;
            repo.submit_speech(&p,"page-b",&"b".repeat(64),&ts,None).await.unwrap();
            let first:String=sqlx::query_scalar("SELECT item_id FROM tts_submission_items WHERE tenant_id=$1 ORDER BY item_id LIMIT 1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            let request=repo.speech_request(&p.tenant_id,&first).await.unwrap();
            materialize(repo,&p,&request).await;publish(repo,&p,&request).await;
            let trigger=if $sqlite {
                format!("CREATE TRIGGER s17_page_fail BEFORE UPDATE OF receipt ON tts_submission_items WHEN NEW.item_id='{first}' BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;")
            } else {
                format!("CREATE FUNCTION s17_page_fail_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SECRET_SENTINEL'; END $$; CREATE TRIGGER s17_page_fail BEFORE UPDATE OF receipt ON tts_submission_items FOR EACH ROW WHEN (NEW.item_id='{first}') EXECUTE FUNCTION s17_page_fail_fn();")
            };
            sqlx::raw_sql(&trigger).execute(repo.pool()).await.unwrap();
            let mut after=None::<(String,String)>;let mut found=std::collections::HashSet::new();
            let mut attached=0;
            loop {
                let page=repo.pending_speech_attachments(after.as_ref().map(|(t,i)|(t.as_str(),i.as_str())),17).await.unwrap();
                assert!(page.len()<=17);if page.is_empty(){break}
                for (tenant,item) in &page {
                    let result=repo.resolve_speech_attachment(tenant,item).await;
                    if item==&first {assert!(result.is_err());}else{result.unwrap();}
                    if tenant==&p.tenant_id {
                        assert!(found.insert(item.clone()));
                        if item!=&first {attached+=1;}
                    }
                }
                after=page.last().cloned();
            }
            assert_eq!(found.len(),102);assert_eq!(attached,101);
            let committed:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tts_submission_items WHERE tenant_id=$1 AND receipt IS NOT NULL").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(committed,101);
            let drop=if $sqlite {"DROP TRIGGER s17_page_fail;"}else{"DROP TRIGGER s17_page_fail ON tts_submission_items; DROP FUNCTION s17_page_fail_fn();"};
            sqlx::raw_sql(drop).execute(repo.pool()).await.unwrap();
            repo.resolve_speech_attachment(&p.tenant_id,&first).await.unwrap();
            assert!(repo.speech_submission(&p,"page-a",None).await.unwrap().unwrap().complete);
            assert!(repo.speech_submission(&p,"page-b",None).await.unwrap().unwrap().complete);
        }
    };
}
pub(super) use faults;
