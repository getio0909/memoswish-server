//! 仓储一致性测试套件：所有 `Repository` 实现都必须通过。
//!
//! 每次运行使用随机租户 ID，可在持久化数据库上重复执行。

use chrono::{Duration, Utc};
use memoswish_core::Role;
use memoswish_core::ids::new_id;
use memoswish_core::repo::*;
use memoswish_protocol::examples;

/// 依次验证各仓储接口的行为契约。
pub async fn run<R: Repository>(repo: &R) {
    let t1 = format!("t_{}", new_id());
    let t2 = format!("t_{}", new_id());
    let now = Utc::now();

    // ---- 租户与用户 ----
    for t in [&t1, &t2] {
        repo.upsert_tenant(&TenantRecord { id: t.clone(), name: "Test".into(), plan: "free".into(), created_at: now })
            .await
            .unwrap();
    }
    assert_eq!(repo.get_tenant(&t1).await.unwrap().unwrap().plan, "free");
    let email = format!("{}@Example.com", new_id());
    let user = UserRecord {
        id: new_id(),
        tenant_id: t1.clone(),
        email: email.clone(),
        display_name: "Ada".into(),
        password_hash: "hash".into(),
        role: Role::Editor,
        created_at: now,
    };
    repo.insert_user(&user).await.unwrap();
    let found = repo.find_user_by_email(&email.to_uppercase()).await.unwrap().unwrap();
    assert_eq!(found.id, user.id);
    assert_eq!(found.role, Role::Editor);
    assert!(repo.insert_user(&user).await.is_err(), "duplicate email must fail");
    assert!(repo.get_user(&t2, &user.id).await.unwrap().is_none(), "tenant isolation");

    crate::oauth_conformance::run(repo, &user).await;
    crate::identity_conformance::run(repo).await;

    // ---- API Token ----
    let token = ApiTokenRecord {
        generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
        id: new_id(),
        tenant_id: t1.clone(),
        user_id: user.id.clone(),
        name: "agent".into(),
        token_hash: format!("hash_{}", new_id()),
        scopes: vec!["content:write".into()],
        created_at: now,
        expires_at: Some(now + Duration::days(30)),
        last_used_at: None,
        revoked: false,
    };
    repo.insert_api_token(&token).await.unwrap();
    let got = repo.find_api_token(&token.token_hash).await.unwrap().unwrap();
    assert_eq!(got.scopes, token.scopes);
    repo.touch_api_token(&token.id, now).await.unwrap();
    assert!(repo.find_api_token(&token.token_hash).await.unwrap().unwrap().last_used_at.is_some());
    assert!(!repo.revoke_api_token(&t2, &token.id).await.unwrap(), "cannot revoke other tenant's token");
    assert!(repo.revoke_api_token(&t1, &token.id).await.unwrap());
    assert!(repo.find_api_token(&token.token_hash).await.unwrap().unwrap().revoked);
    assert_eq!(repo.list_api_tokens(&t1).await.unwrap().len(), 1);

    // ---- 用量计数 ----
    assert_eq!(repo.add_usage(&t1, "tts_chars", "2026-10", 5).await.unwrap(), 5);
    assert_eq!(repo.add_usage(&t1, "tts_chars", "2026-10", 7).await.unwrap(), 12);
    assert_eq!(repo.get_usage(&t1, "tts_chars", "2026-10").await.unwrap(), 12);
    assert_eq!(repo.get_usage(&t2, "tts_chars", "2026-10").await.unwrap(), 0);

    // ---- 卡组与卡片 ----
    let deck = examples::sample_deck();
    repo.insert_deck(&t1, &deck).await.unwrap();
    let card = examples::sample_card();
    let code = examples::sample_rich_card();
    repo.insert_card(&t1, &card).await.unwrap();
    let mut code_in_deck = code.clone();
    code_in_deck.deck_id = deck.id.clone();
    repo.insert_card(&t1, &code_in_deck).await.unwrap();
    assert_eq!(repo.get_card(&t1, &card.id).await.unwrap().unwrap(), card);
    assert!(repo.get_card(&t2, &card.id).await.unwrap().is_none(), "tenant isolation");
    assert_eq!(repo.get_deck(&t1, &deck.id).await.unwrap().unwrap().card_count, 2);
    assert_eq!(repo.list_cards(&t1, Some(&deck.id), 10, 0).await.unwrap().len(), 2);
    assert_eq!(repo.list_cards(&t1, None, 1, 1).await.unwrap().len(), 1);
    assert_eq!(repo.list_decks(&t1).await.unwrap().len(), 1);
    assert!(repo.list_decks(&t2).await.unwrap().is_empty());
    let mut updated = card.clone();
    updated.revision += 1;
    updated.front.title = "serendipitous".into();
    let draft = memoswish_protocol::CardDraft {
        id: Some(updated.id.clone()),
        expected_revision: Some(card.revision),
        deck_id: updated.deck_id.clone(),
        template: Some(updated.template.clone()),
        language: Some(updated.language.clone()),
        front: updated.front.clone(),
        back: updated.back.clone(),
        tags: updated.tags.clone(),
        attributes: updated.attributes.clone(),
        ducking: None,
        visual: None,
    };
    repo.mutate_cards(&t1, &[memoswish_core::content::CardMutation::Draft { id: updated.id.clone(), draft }])
        .await
        .unwrap();
    assert_eq!(repo.get_card(&t1, &card.id).await.unwrap().unwrap().front.title, "serendipitous");
    assert!(repo.delete_card(&t1, &code.id).await.unwrap());
    assert!(!repo.delete_card(&t1, &code.id).await.unwrap());

    // 新卡组与卡片必须整体提交；第二张卡与已有行冲突时第一张也回滚。
    let mut imported_deck = deck.clone();
    imported_deck.id = new_id();
    let mut fresh = card.clone();
    fresh.id = new_id();
    fresh.deck_id = imported_deck.id.clone();
    let mut conflicting = card.clone();
    conflicting.deck_id = imported_deck.id.clone();
    assert!(repo.insert_deck_with_cards(&t1, &imported_deck, &[fresh.clone(), conflicting]).await.is_err());
    assert!(repo.get_deck(&t1, &imported_deck.id).await.unwrap().is_none());
    assert!(repo.get_card(&t1, &fresh.id).await.unwrap().is_none());
    assert_eq!(repo.get_card(&t1, &card.id).await.unwrap().unwrap().front.title, "serendipitous");
    assert!(repo.insert_deck_with_cards(&t1, &imported_deck, std::slice::from_ref(&card)).await.is_err());
    assert!(repo.insert_deck_with_cards(&t1, &imported_deck, &[fresh.clone(), fresh.clone()]).await.is_err());
    repo.insert_deck_with_cards(&t1, &imported_deck, std::slice::from_ref(&fresh)).await.unwrap();
    assert_eq!(repo.get_deck(&t1, &imported_deck.id).await.unwrap().unwrap().card_count, 1);
    assert!(repo.get_deck(&t2, &imported_deck.id).await.unwrap().is_none());
    assert!(repo.get_card(&t2, &fresh.id).await.unwrap().is_none());
    repo.insert_deck_with_cards(&t2, &imported_deck, &[fresh]).await.unwrap();
    repo.delete_deck(&t1, &imported_deck.id).await.unwrap();
    assert!(repo.get_deck(&t2, &imported_deck.id).await.unwrap().is_some());
    repo.delete_deck(&t2, &imported_deck.id).await.unwrap();

    // 并发争夺最后一个额度，只允许一次成功且失败不改变计数。
    assert_eq!(repo.try_add_usage(&t1, "bounded", "2026-11", 11, 10).await.unwrap(), None);
    assert_eq!(repo.get_usage(&t1, "bounded", "2026-11").await.unwrap(), 0);
    assert_eq!(repo.try_add_usage(&t1, "bounded", "2026-11", 9, 10).await.unwrap(), Some(9));
    let (a, b) = tokio::join!(
        repo.try_add_usage(&t1, "bounded", "2026-11", 1, 10),
        repo.try_add_usage(&t1, "bounded", "2026-11", 1, 10)
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|v| v.is_some()).count(), 1);
    assert_eq!(repo.get_usage(&t1, "bounded", "2026-11").await.unwrap(), 10);
    assert_eq!(repo.get_usage(&t2, "bounded", "2026-11").await.unwrap(), 0);
    let (a, b) = tokio::join!(
        repo.try_add_usage(&t1, "new-counter", "2026-11", 1, 1),
        repo.try_add_usage(&t1, "new-counter", "2026-11", 1, 1)
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|v| v.is_some()).count(), 1);
    assert!(repo.try_add_usage(&t1, "bounded", "2026-11", -1, 10).await.is_err());

    // ---- BGM ----
    let shared = examples::sample_bgm_track();
    repo.save_bgm(None, &shared, None).await.unwrap();
    let mut private = shared.clone();
    private.title = "Private Remix".into();
    repo.save_bgm(Some(&t1), &private, None).await.unwrap();
    assert_eq!(repo.get_bgm(&t1, &shared.id).await.unwrap().unwrap().title, "Private Remix");
    assert_eq!(repo.get_bgm(&t2, &shared.id).await.unwrap().unwrap().title, shared.title);

    // ---- 记忆状态 ----
    let mem = MemoryState {
        tenant_id: t1.clone(),
        user_id: user.id.clone(),
        card_id: card.id.clone(),
        stability: 3.2,
        difficulty: 5.5,
        reps: 1,
        lapses: 0,
        exposures: 1,
        last_review: Some(now),
        due: Some(now + Duration::days(3)),
        starred: true,
        last_rating: Some(3),
    };
    repo.upsert_memory(&mem).await.unwrap();
    let got = repo.get_memory(&t1, &user.id, &card.id).await.unwrap().unwrap();
    assert!((got.stability - 3.2).abs() < 1e-9);
    assert!(got.starred);
    assert_eq!(repo.list_memory(&t1, &user.id).await.unwrap().len(), 1);
    assert!(repo.list_memory(&t2, &user.id).await.unwrap().is_empty());

    // ---- 埋点幂等 ----
    let batch = examples::sample_feedback_batch();
    let rec = FeedbackEventRecord {
        tenant_id: t1.clone(),
        user_id: user.id.clone(),
        session_id: batch.session_id.clone(),
        event: batch.events[0].clone(),
        rating: Some(2),
        received_at: now,
        application: None,
    };
    assert!(repo.insert_feedback(&rec).await.unwrap());
    assert!(!repo.insert_feedback(&rec).await.unwrap());

    // ---- 信息流会话 ----
    let mut sess = FeedSession {
        id: new_id(),
        tenant_id: t1.clone(),
        user_id: user.id.clone(),
        next_slot: 0,
        recent_card_ids: vec![],
        created_at: now,
        updated_at: now,
    };
    repo.save_session(&sess).await.unwrap();
    sess.next_slot = 10;
    sess.recent_card_ids = vec![card.id.clone()];
    repo.save_session(&sess).await.unwrap();
    let got = repo.get_session(&t1, &user.id, &sess.id).await.unwrap().unwrap();
    assert_eq!(got.next_slot, 10);
    assert_eq!(got.recent_card_ids, vec![card.id.clone()]);
    assert!(repo.get_session(&t2, &user.id, &sess.id).await.unwrap().is_none());

    // ---- 级联删除 ----
    assert!(repo.delete_deck(&t1, &deck.id).await.unwrap());
    assert!(repo.get_card(&t1, &card.id).await.unwrap().is_none());
}
