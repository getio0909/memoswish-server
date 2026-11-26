//! 学习控制与 FSRS 记忆分离，调用必须显式指定租户并复核原凭据。
use crate::{CoreError, CoreResult, Principal};
use async_trait::async_trait;
use memoswish_protocol::*;

pub fn validate_retention(value: Option<f64>) -> CoreResult<()> {
    if value.is_some_and(|v| !v.is_finite() || !(0.50..=0.99).contains(&v)) {
        return Err(CoreError::invalid("retention must be finite and within [0.50, 0.99]"));
    }
    Ok(())
}
#[async_trait]
pub trait LearningControlsRepo: Send + Sync {
    async fn learner_preferences(&self, tenant_id: &str, p: &Principal, default: f64)
    -> CoreResult<LearnerPreferences>;
    async fn set_retention(
        &self,
        tenant_id: &str,
        p: &Principal,
        command: &RetentionCommand,
        default: f64,
    ) -> CoreResult<LearnerPreferences>;
    async fn card_control(&self, tenant_id: &str, p: &Principal, card: &str) -> CoreResult<LearnerCardControl>;
    async fn set_card_control(
        &self,
        tenant_id: &str,
        p: &Principal,
        card: &str,
        command: &CardControlCommand,
    ) -> CoreResult<LearnerCardControl>;
    async fn hidden_cards(
        &self,
        tenant_id: &str,
        p: &Principal,
        after: Option<&str>,
        limit: u32,
    ) -> CoreResult<HiddenCardsPage>;
}
