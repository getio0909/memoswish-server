//! 学习控制只转交领域服务，不暴露存储实现。
use crate::Services;
use memoswish_core::{CoreResult, Principal};
use memoswish_protocol::*;
impl Services {
    pub async fn learner_preferences(&self, p: &Principal) -> CoreResult<LearnerPreferences> {
        self.feed.learner_preferences(p).await
    }
    pub async fn set_retention(&self, p: &Principal, command: &RetentionCommand) -> CoreResult<LearnerPreferences> {
        self.feed.set_retention(p, command).await
    }
    pub async fn card_control(&self, p: &Principal, card: &str) -> CoreResult<LearnerCardControl> {
        self.feed.card_control(p, card).await
    }
    pub async fn set_card_control(
        &self,
        p: &Principal,
        card: &str,
        command: &CardControlCommand,
    ) -> CoreResult<LearnerCardControl> {
        self.feed.set_card_control(p, card, command).await
    }
    pub async fn hidden_cards(&self, p: &Principal, after: Option<&str>, limit: u32) -> CoreResult<HiddenCardsPage> {
        self.feed.hidden_cards(p, after, limit).await
    }
}
