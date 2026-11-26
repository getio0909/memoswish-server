//! 生命周期仓储显式绑定租户和原始主体。
use crate::{CoreResult, Principal, content::CardMutation};
use async_trait::async_trait;
use memoswish_protocol::*;
#[async_trait]
pub trait ContentLifecycleRepo: Send + Sync {
    async fn insert_authored_deck(&self, tenant_id: &str, principal: &Principal, deck: &Deck) -> CoreResult<()>;
    async fn author_cards(
        &self,
        tenant_id: &str,
        principal: &Principal,
        mutations: &[CardMutation],
    ) -> CoreResult<Vec<Card>>;
    async fn author_card(
        &self,
        tenant_id: &str,
        principal: &Principal,
        mutation: &CardMutation,
        report_id: Option<&str>,
    ) -> CoreResult<Card>;
    async fn edit_deck(
        &self,
        tenant_id: &str,
        principal: &Principal,
        deck_id: &str,
        edit: &DeckEdit,
    ) -> CoreResult<Deck>;
    async fn content_revisions(
        &self,
        tenant_id: &str,
        principal: &Principal,
        card_id: &str,
        before: u64,
        limit: u32,
    ) -> CoreResult<Vec<CardRevision>>;
    async fn create_content_report(
        &self,
        tenant_id: &str,
        principal: &Principal,
        card_id: &str,
        report: &ReportCreate,
    ) -> CoreResult<ContentReport>;
    async fn content_reports(
        &self,
        tenant_id: &str,
        principal: &Principal,
        card_id: &str,
        offset: u32,
        limit: u32,
    ) -> CoreResult<Vec<ContentReport>>;
    async fn visible_cards(
        &self,
        tenant_id: &str,
        deck_id: Option<&str>,
        drafts: bool,
        limit: u32,
        offset: u32,
    ) -> CoreResult<Vec<Card>>;
}
