//! 资料库门面复用既有仓储、授权与资产渲染。
use crate::Services;
use memoswish_core::{CoreResult, Principal};
use memoswish_protocol::*;
impl Services {
    pub async fn library_page(&self, p: &Principal, q: &LibraryQuery) -> CoreResult<LibraryPage> {
        let mut page = self.content.explanation_repository().library_page(p, q).await?;
        for entry in &mut page.items {
            entry.card = crate::asset_delivery::render_card(entry.card.clone(), "content");
        }
        Ok(page)
    }
    pub async fn review_history(&self, p: &Principal, q: &LibraryQuery) -> CoreResult<ReviewHistoryPage> {
        self.content.explanation_repository().review_history(p, q).await
    }
    pub async fn set_favorite(&self, p: &Principal, card: &str, c: &FavoriteCommand) -> CoreResult<FavoriteState> {
        self.content.explanation_repository().set_favorite(p, card, c).await
    }
}
