//! 严格内容命令；发布只改变租户内学习资格。
use crate::ContentService;
use memoswish_core::{CoreResult, Permission, Principal, content::CardMutation, ids::new_id};
use memoswish_protocol::*;
impl ContentService {
    pub async fn create_authored_deck(&self, p: &Principal, input: crate::NewDeck) -> CoreResult<Deck> {
        p.require(Permission::ContentWrite)?;
        if input.title.trim().is_empty()
            || input.title.chars().count() > 200
            || input.description.len() > 16384
            || input.language.trim().is_empty()
            || input.language.len() > 64
        {
            return Err(memoswish_core::CoreError::invalid("invalid deck metadata"));
        }
        let deck = Deck {
            revision: Some(1),
            id: new_id(),
            title: input.title.trim().into(),
            description: input.description,
            language: input.language,
            tags: input.tags,
            card_count: 0,
            created_at: chrono::Utc::now(),
        };
        self.repo.insert_authored_deck(&p.tenant_id, p, &deck).await?;
        Ok(deck)
    }
    pub async fn save_card(&self, p: &Principal, save: CardSave) -> CoreResult<Card> {
        p.require(Permission::ContentWrite)?;
        memoswish_core::content_lifecycle::validate_save(&save)?;
        let report = save.report_id.clone();
        let change = CardMutation::Author {
            id: save.card.id.clone().unwrap_or_else(new_id),
            save: Box::new(save),
            observed_generation: None,
        };
        self.repo.author_card(&p.tenant_id, p, &change, report.as_deref()).await
    }
    pub async fn publish_card(&self, p: &Principal, id: &str, command: PublicationCommand) -> CoreResult<Card> {
        p.require(Permission::ContentWrite)?;
        self.repo.author_card(&p.tenant_id, p, &CardMutation::Publication { id: id.into(), command }, None).await
    }
    pub async fn edit_deck(&self, p: &Principal, id: &str, edit: &DeckEdit) -> CoreResult<Deck> {
        p.require(Permission::ContentWrite)?;
        self.repo.edit_deck(&p.tenant_id, p, id, edit).await
    }
    pub async fn revisions(&self, p: &Principal, id: &str, before: u64, limit: u32) -> CoreResult<Vec<CardRevision>> {
        self.repo.content_revisions(&p.tenant_id, p, id, before, limit).await
    }
    pub async fn report(&self, p: &Principal, id: &str, report: &ReportCreate) -> CoreResult<ContentReport> {
        self.repo.create_content_report(&p.tenant_id, p, id, report).await
    }
    pub async fn reports(&self, p: &Principal, id: &str, offset: u32, limit: u32) -> CoreResult<Vec<ContentReport>> {
        self.repo.content_reports(&p.tenant_id, p, id, offset, limit).await
    }
}

impl ContentService {
    pub async fn save_generated_cards(
        &self,
        p: &Principal,
        drafts: Vec<CardDraft>,
        publish: bool,
        method: &str,
    ) -> CoreResult<Vec<Card>> {
        p.require(Permission::ContentWrite)?;
        let changes = drafts
            .into_iter()
            .map(|card| {
                let save = CardSave {
                    card,
                    publish,
                    provenance: Some(ContentProvenance { method: method.into(), ..Default::default() }),
                    report_id: None,
                };
                CardMutation::Author {
                    id: save.card.id.clone().unwrap_or_else(new_id),
                    save: Box::new(save),
                    observed_generation: (method == "heuristic").then(|| "builtin-heuristic".into()),
                }
            })
            .collect::<Vec<_>>();
        self.repo.author_cards(&p.tenant_id, p, &changes).await
    }
}
