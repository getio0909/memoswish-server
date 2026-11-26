//! 个人学习状态的事务查询与显式命令。
use crate::{CoreResult, Principal};
use async_trait::async_trait;
use memoswish_protocol::{
    FavoriteCommand, FavoriteState, FeedbackReceipt, LibraryPage, LibraryQuery, ReviewHistoryPage,
};
#[async_trait]
pub trait LibraryRepo: Send + Sync {
    async fn set_favorite(&self, p: &Principal, card: &str, command: &FavoriteCommand) -> CoreResult<FavoriteState>;
    async fn library_page(&self, p: &Principal, query: &LibraryQuery) -> CoreResult<LibraryPage>;
    async fn review_history(&self, p: &Principal, query: &LibraryQuery) -> CoreResult<ReviewHistoryPage>;
    async fn feedback_receipts(&self, p: &Principal, ids: &[String]) -> CoreResult<Vec<FeedbackReceipt>>;
}
