//! 学习控制查询与命令经同一仓储边界复核授权，建议保持率仅作建议。
use crate::FeedService;
use memoswish_core::{CoreResult, Principal};
use memoswish_protocol::*;
impl FeedService {
    pub async fn learner_preferences(&self, p: &Principal) -> CoreResult<LearnerPreferences> {
        self.repo.learner_preferences(&p.tenant_id, p, self.cfg.desired_retention).await
    }
    pub async fn set_retention(&self, p: &Principal, command: &RetentionCommand) -> CoreResult<LearnerPreferences> {
        self.repo.set_retention(&p.tenant_id, p, command, self.cfg.desired_retention).await
    }
    pub async fn card_control(&self, p: &Principal, card: &str) -> CoreResult<LearnerCardControl> {
        self.repo.card_control(&p.tenant_id, p, card).await
    }
    pub async fn set_card_control(
        &self,
        p: &Principal,
        card: &str,
        command: &CardControlCommand,
    ) -> CoreResult<LearnerCardControl> {
        self.repo.set_card_control(&p.tenant_id, p, card, command).await
    }
    pub async fn hidden_cards(&self, p: &Principal, after: Option<&str>, limit: u32) -> CoreResult<HiddenCardsPage> {
        self.repo.hidden_cards(&p.tenant_id, p, after, limit).await
    }
}
