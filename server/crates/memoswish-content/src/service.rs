//! 内容服务。

use std::sync::Arc;

use chrono::Utc;
use memoswish_core::content::CardMutation;
use memoswish_core::ids::new_id;
use memoswish_core::repo::Repository;
use memoswish_core::{CoreError, CoreResult, Permission, Principal};
use memoswish_protocol::{BgmBinding, Card, CardExplanation, Deck, DeckPack, ExplainRequest, TtsTrack};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::explain::{AiExplainConfig, explain_card};

/// 新建卡组参数。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NewDeck {
    /// 卡组标题。
    pub title: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// BCP-47 语言标签，例如 `en-US`。
    pub language: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub use memoswish_protocol::CardDraft;

/// 内容服务。
#[derive(Clone)]
pub struct ContentService {
    pub(crate) observer: Arc<dyn memoswish_core::observability::Observer>,
    pub(crate) repo: Arc<dyn Repository>,
    pub(crate) import_store: Option<Arc<dyn memoswish_core::store::ObjectStore>>,
    ai: AiExplainConfig,
    pub(crate) import_staging_limit: i64,
    privacy: memoswish_protocol::PrivacyPolicy,
    execute_external_ai: bool,
    pub(crate) execute_imports: bool,
}

impl ContentService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self {
            observer: memoswish_core::observability::noop(),
            repo,
            import_store: None,
            ai: AiExplainConfig::default(),
            import_staging_limit: 2,
            privacy: Default::default(),
            execute_external_ai: true,
            execute_imports: true,
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn memoswish_core::observability::Observer>) -> Self {
        observer.capacity(memoswish_core::observability::AdmissionClass::Explanation, 0, 8);
        observer.capacity(memoswish_core::observability::AdmissionClass::Import, 0, 2);
        self.observer = observer;
        self
    }

    pub fn explanation_observer(&self) -> Arc<dyn memoswish_core::observability::Observer> {
        self.observer.clone()
    }

    /// 外部处理使用独立用途版本，不从模型配置推导同意。
    pub fn with_privacy_policy(mut self, policy: memoswish_protocol::PrivacyPolicy) -> Self {
        self.privacy = policy;
        self
    }

    /// 配置外部 OpenAI 兼容模型（未配置时自动使用内置启发式解析）。
    pub fn with_ai_config(mut self, ai: AiExplainConfig) -> Self {
        self.ai = ai;
        self
    }

    /// 无执行权限的角色拒绝已配置的外部解释；未配置时仍可使用内置解析。
    pub fn with_external_ai_execution(mut self, enabled: bool) -> Self {
        self.execute_external_ai = enabled;
        self
    }

    /// 应用门面复用同一仓储和不可变解释配置。
    pub fn explanation_repository(&self) -> Arc<dyn Repository> {
        self.repo.clone()
    }
    pub fn explanation_config(&self) -> &AiExplainConfig {
        &self.ai
    }

    pub async fn create_deck(&self, p: &Principal, d: NewDeck) -> CoreResult<Deck> {
        p.require(Permission::ContentWrite)?;
        if d.title.trim().is_empty() {
            return Err(CoreError::invalid("deck title is required"));
        }
        if d.language.trim().is_empty() {
            return Err(CoreError::invalid("deck language is required"));
        }
        let deck = Deck {
            revision: Some(1),
            id: new_id(),
            title: d.title.trim().into(),
            description: d.description,
            language: d.language,
            tags: d.tags,
            card_count: 0,
            created_at: Utc::now(),
        };
        self.repo.insert_deck(&p.tenant_id, &deck).await?;
        Ok(deck)
    }

    pub async fn list_decks(&self, p: &Principal) -> CoreResult<Vec<Deck>> {
        p.require(Permission::ContentRead)?;
        let mut decks = self.repo.list_decks(&p.tenant_id).await?;
        if !p.can(Permission::ContentWrite) {
            for deck in &mut decks {
                deck.card_count = self.repo.feed_summary(&p.tenant_id, &p.user_id, Some(&deck.id)).await?.total_cards;
            }
        }
        Ok(decks)
    }

    pub async fn get_deck(&self, p: &Principal, deck_id: &str) -> CoreResult<Deck> {
        p.require(Permission::ContentRead)?;
        self.repo.get_deck(&p.tenant_id, deck_id).await?.ok_or_else(|| CoreError::NotFound(format!("deck `{deck_id}`")))
    }

    pub async fn delete_deck(&self, p: &Principal, deck_id: &str) -> CoreResult<()> {
        p.require(Permission::ContentWrite)?;
        if self.repo.delete_deck(&p.tenant_id, deck_id).await? {
            Ok(())
        } else {
            Err(CoreError::NotFound(format!("deck `{deck_id}`")))
        }
    }

    /// 普通内容批次在一个短事务中校验、合并和提交。
    pub async fn upsert_cards(&self, p: &Principal, drafts: Vec<CardDraft>) -> CoreResult<Vec<Card>> {
        p.require(Permission::ContentWrite)?;
        if drafts.is_empty() || drafts.len() > 200 {
            return Err(CoreError::invalid("provide 1..=200 cards per call"));
        }
        let changes: Vec<_> = drafts
            .into_iter()
            .map(|draft| CardMutation::Draft { id: draft.id.clone().unwrap_or_else(new_id), draft })
            .collect();
        self.repo.mutate_cards(&p.tenant_id, &changes).await
    }

    pub async fn get_card(&self, p: &Principal, card_id: &str) -> CoreResult<Card> {
        p.require(Permission::ContentRead)?;
        self.repo
            .get_card(&p.tenant_id, card_id)
            .await?
            .filter(|c| p.can(Permission::ContentWrite) || memoswish_core::content_lifecycle::published(c))
            .ok_or_else(|| CoreError::NotFound(format!("card `{card_id}`")))
    }

    pub async fn list_cards(
        &self,
        p: &Principal,
        deck_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> CoreResult<Vec<Card>> {
        p.require(Permission::ContentRead)?;
        self.repo
            .visible_cards(&p.tenant_id, deck_id, p.can(Permission::ContentWrite), limit.clamp(1, 500), offset)
            .await
    }

    /// 只固定目标集合，快照之后的新卡不属于本次命令。
    pub async fn bgm_target_snapshot(&self, p: &Principal, deck_id: &str) -> CoreResult<Vec<String>> {
        self.get_deck(p, deck_id).await?;
        let cards = self.repo.list_cards(&p.tenant_id, Some(deck_id), 501, 0).await?;
        if cards.len() > 500 {
            return Err(CoreError::invalid("deck BGM assignment supports at most 500 cards"));
        }
        Ok(cards.into_iter().map(|c| c.id).collect())
    }

    pub async fn delete_card(&self, p: &Principal, card_id: &str) -> CoreResult<()> {
        self.delete_card_if_revision(p, card_id, None).await
    }

    pub async fn delete_card_if_revision(
        &self,
        p: &Principal,
        card_id: &str,
        expected_revision: Option<u32>,
    ) -> CoreResult<()> {
        p.require(Permission::ContentWrite)?;
        if self.repo.delete_card_if_revision(&p.tenant_id, card_id, expected_revision).await? {
            Ok(())
        } else {
            Err(CoreError::NotFound(format!("card `{card_id}`")))
        }
    }

    /// 合成前的版本必须保留到挂载时，禁止旧语音污染新内容。
    pub async fn attach_tts(
        &self,
        p: &Principal,
        card_id: &str,
        expected_revision: u32,
        tts: TtsTrack,
    ) -> CoreResult<Card> {
        p.require(Permission::ContentWrite)?;
        p.require(Permission::ContentRead)?;
        let changes = [CardMutation::Tts { id: card_id.into(), expected_revision, track: tts }];
        Ok(self.repo.mutate_cards(&p.tenant_id, &changes).await?.remove(0))
    }

    /// 一次挂载或移除整个目标批次的 BGM。
    pub async fn attach_bgm_batch(
        &self,
        p: &Principal,
        targets: &[(String, Option<u32>)],
        bgm: Option<BgmBinding>,
    ) -> CoreResult<Vec<Card>> {
        p.require(Permission::ContentWrite)?;
        p.require(Permission::ContentRead)?;
        let changes: Vec<_> = targets
            .iter()
            .map(|(id, expected_revision)| CardMutation::Bgm {
                id: id.clone(),
                expected_revision: *expected_revision,
                binding: bgm.clone(),
            })
            .collect();
        self.repo.mutate_cards(&p.tenant_id, &changes).await
    }

    /// 导出整个卡组及其全部卡片为可移植内容包（DeckPack）。
    pub async fn export_deck(&self, p: &Principal, deck_id: &str) -> CoreResult<DeckPack> {
        p.require(Permission::ContentRead)?;
        let mut deck = self.get_deck(p, deck_id).await?;
        let cards =
            self.repo.visible_cards(&p.tenant_id, Some(deck_id), p.can(Permission::ContentWrite), 5_000, 0).await?;
        deck.card_count = cards.len() as u32;
        Ok(DeckPack {
            version: if cards.iter().any(memoswish_core::bgm::has_media_metadata) {
                "1.2"
            } else if cards.iter().any(|c| c.content.is_some()) {
                "1.1"
            } else {
                "1.0"
            }
            .into(),
            deck,
            cards,
            exported_at: Utc::now(),
        })
    }

    /// 导入卡组内容包（DeckPack）：创建新卡组并批量写入包内卡片，返回更新计数后的卡组。
    pub async fn import_deck_pack(&self, p: &Principal, pack: DeckPack) -> CoreResult<Deck> {
        let work = self.prepare_deck_pack(p, pack, false)?;
        let authority = memoswish_core::imports::ImportAuthority::capture(p, None);
        let key = new_id();
        let fingerprint = crate::imports::fingerprint("deckpack", &work, false)?;
        let operation =
            self.repo.accept_import(&authority, &key, &fingerprint, &work, None, self.import_staging_limit).await?;
        let result = crate::imports::import_result(self.drive_import(&p.tenant_id, &operation.id).await?)?;
        serde_json::from_value(result).map_err(CoreError::internal)
    }

    /// 生成指定卡片的 AI 深度解析（长按抽屉）。
    pub async fn explain_card(
        &self,
        p: &Principal,
        card_id: &str,
        req: &ExplainRequest,
    ) -> CoreResult<CardExplanation> {
        p.require(Permission::ContentRead)?;
        let card = self.get_card(p, card_id).await?;
        // 先保留权限与租户查找语义，再在任何外部调用前检查角色权限。
        if !self.execute_external_ai && self.ai.external_enabled() {
            return Err(CoreError::Unavailable("external explanation execution is not available in this role".into()));
        }
        crate::explain::validate_input(&card, req)?;
        let revision = if self.ai.base_url.is_some() {
            let state = self.repo.privacy_state(&p.tenant_id, p).await?;
            if memoswish_core::privacy::require_purpose(&state, &self.privacy, "external_ai").is_err() {
                return explain_card(&card, req, &AiExplainConfig::default()).await;
            }
            Some(self.repo.privacy_admit(&p.tenant_id, p, &self.privacy, Some("external_ai"), None).await?)
        } else {
            None
        };
        let result = crate::explain::explain_card(&card, req, &self.ai).await?;
        if let Some(revision) = revision {
            self.repo.privacy_admit(&p.tenant_id, p, &self.privacy, Some("external_ai"), Some(revision)).await?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_protocol::CardFace;
    use memoswish_storage::sqlite::SqliteRepository;

    fn face(t: &str) -> CardFace {
        CardFace::simple(t, "")
    }

    #[tokio::test]
    async fn crud_and_revision_bump() {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        repo.upsert_tenant(&memoswish_core::repo::TenantRecord {
            id: "local".into(),
            name: "Local test".into(),
            plan: "self_hosted".into(),
            created_at: memoswish_protocol::examples::sample_deck().created_at,
        })
        .await
        .unwrap();
        repo.insert_user(&memoswish_core::repo::UserRecord {
            id: "usr_local".into(),
            tenant_id: "local".into(),
            email: "local@example.com".into(),
            display_name: "Owner".into(),
            password_hash: String::new(),
            role: memoswish_core::Role::Owner,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
        let svc = ContentService::new(repo);
        let p = Principal::local_owner("test");
        let deck = svc
            .create_deck(
                &p,
                NewDeck { title: "Rust".into(), description: String::new(), language: "en-US".into(), tags: vec![] },
            )
            .await
            .unwrap();
        let draft = CardDraft {
            id: None,
            expected_revision: None,
            deck_id: deck.id.clone(),
            template: Some("concept".into()),
            language: None,
            front: face("Ownership"),
            back: face("Each value has one owner."),
            tags: vec![],
            attributes: serde_json::Map::new(),
            ducking: None,
            visual: None,
        };
        let created = svc.upsert_cards(&p, vec![draft.clone()]).await.unwrap().remove(0);
        assert_eq!(created.revision, 1);
        assert_eq!(created.language, "en-US");
        assert_eq!(created.template, "concept");

        let mut upd = draft.clone();
        upd.id = Some(created.id.clone());
        upd.front = face("Ownership rules");
        let updated = svc.upsert_cards(&p, vec![upd]).await.unwrap().remove(0);
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.created_at, created.created_at);

        let mut bad = draft;
        bad.deck_id = "missing".into();
        assert!(svc.upsert_cards(&p, vec![bad]).await.is_err());

        let mut learner = p.clone();
        learner.role = memoswish_core::Role::Learner;
        assert!(svc.delete_card(&learner, &created.id).await.is_err());
        svc.delete_card(&p, &created.id).await.unwrap();
        assert!(svc.get_card(&p, &created.id).await.is_err());
    }

    #[tokio::test]
    async fn export_import_and_explain() {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        repo.upsert_tenant(&memoswish_core::repo::TenantRecord {
            id: "local".into(),
            name: "Local test".into(),
            plan: "self_hosted".into(),
            created_at: memoswish_protocol::examples::sample_deck().created_at,
        })
        .await
        .unwrap();
        repo.insert_user(&memoswish_core::repo::UserRecord {
            id: "usr_local".into(),
            tenant_id: "local".into(),
            email: "local@example.com".into(),
            display_name: "Owner".into(),
            password_hash: String::new(),
            role: memoswish_core::Role::Owner,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
        let svc = ContentService::new(repo);
        let p = Principal::local_owner("test");
        let deck = svc
            .create_deck(
                &p,
                NewDeck {
                    title: "Algorithms".into(),
                    description: "Core CS concepts".into(),
                    language: "en-US".into(),
                    tags: vec!["cs".into()],
                },
            )
            .await
            .unwrap();
        let drafts = vec![
            CardDraft {
                id: None,
                expected_revision: None,
                deck_id: deck.id.clone(),
                template: Some("concept".into()),
                language: None,
                front: CardFace::simple("Binary Search", "Divide and conquer on sorted arrays"),
                back: CardFace::simple("O(log n)", "Halves the search space at each step."),
                tags: vec!["search".into()],
                attributes: serde_json::Map::new(),
                ducking: None,
                visual: None,
            },
            CardDraft {
                id: None,
                expected_revision: None,
                deck_id: deck.id.clone(),
                template: Some("term".into()),
                language: None,
                front: CardFace::simple("Idempotence", ""),
                back: CardFace::simple("Applying an operation multiple times yields the same result.", ""),
                tags: vec!["distributed".into()],
                attributes: serde_json::Map::new(),
                ducking: None,
                visual: None,
            },
        ];
        let created = svc.upsert_cards(&p, drafts).await.unwrap();
        assert_eq!(created.len(), 2);

        let exp = svc
            .explain_card(
                &p,
                &created[0].id,
                &ExplainRequest {
                    request_id: None, question: Some("时间复杂度为什么是对数？".into()), locale: None
                },
            )
            .await
            .unwrap();
        assert_eq!(exp.card_id, created[0].id);
        assert!(exp.summary.contains("Binary Search"));
        assert!(!exp.key_points.is_empty());

        let pack = svc.export_deck(&p, &deck.id).await.unwrap();
        assert_eq!(pack.version, "1.0");
        assert_eq!(pack.deck.title, "Algorithms");
        assert_eq!(pack.deck.card_count, 2);
        assert_eq!(pack.cards.len(), 2);

        let old_ids: Vec<_> = pack.cards.iter().map(|c| c.id.clone()).collect();
        svc.delete_deck(&p, &deck.id).await.unwrap();
        let imported = svc.import_deck_pack(&p, pack).await.unwrap();
        assert_ne!(imported.id, deck.id);
        assert_eq!(imported.title, "Algorithms");
        assert_eq!(imported.card_count, 2);
        let imported_cards = svc.list_cards(&p, Some(&imported.id), 50, 0).await.unwrap();
        assert_eq!(imported_cards.len(), 2);
        assert!(imported_cards.iter().all(|c| !old_ids.contains(&c.id)));
    }
}
