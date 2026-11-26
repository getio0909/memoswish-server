//! 原子学习写入共用的载荷身份与输入边界。

use memoswish_core::repo::{FeedbackEventRecord, LearningEventProvenance, MemoryState};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::ImplicitFeedback;
use sha2::{Digest, Sha256};

pub(crate) fn validate(record: &FeedbackEventRecord, expected: Option<i64>, state: &MemoryState) -> CoreResult<()> {
    if record.tenant_id != state.tenant_id || record.user_id != state.user_id || record.event.card_id != state.card_id {
        return Err(CoreError::invalid("learning event and projection scopes must match"));
    }
    if expected.is_some_and(|v| v < 0 || v == i64::MAX) {
        return Err(CoreError::invalid("invalid projection version"));
    }
    if !record.event.swipe_velocity.is_finite() || record.event.swipe_velocity < 0.0 {
        return Err(CoreError::invalid("invalid swipe_velocity"));
    }
    Ok(())
}

/// 版本与内容修订来自受保护的接受事务，不信任事务外读取的内容版本。
pub(crate) fn provenance(
    record: &FeedbackEventRecord,
    expected: Option<i64>,
    revision: i64,
) -> Result<LearningEventProvenance, sqlx::Error> {
    let application = record
        .application
        .clone()
        .ok_or_else(|| sqlx::Error::Protocol("missing learning application policy".into()))?;
    if (application.disposition == memoswish_core::repo::LearningDisposition::Scheduled)
        != application.effective_at.is_some()
        || (application.effective_at.is_some() && record.rating.is_none())
    {
        return Err(sqlx::Error::Protocol("inconsistent learning application disposition".into()));
    }
    Ok(LearningEventProvenance {
        application,
        observed_at: record.event.shown_at,
        received_at: record.received_at,
        inferred_rating: record.rating,
        predecessor_version: expected,
        successor_version: expected.map_or(1, |v| v + 1),
        revision_at_acceptance: u32::try_from(revision).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
    })
}

pub(crate) fn payload_hash(session: &str, event: &ImplicitFeedback) -> CoreResult<String> {
    let mut canonical = event.clone();
    // 负零与正零按类型语义视为相同；时间已由 UTC 类型规范化，保留纳秒精度。
    if canonical.swipe_velocity == 0.0 {
        canonical.swipe_velocity = 0.0;
    }
    let bytes = serde_json::to_vec(&(session, canonical)).map_err(CoreError::internal)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn retryable(error: &sqlx::Error) -> bool {
    let Some(error) = error.as_database_error() else { return false };
    matches!(error.code().as_deref(), Some("40001" | "40P01" | "5" | "6" | "261" | "262" | "517" | "773"))
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestPoint {
    BeforeTransaction,
    AfterInsert,
    BeforeCommit,
}

#[cfg(test)]
pub(crate) struct TestGate {
    pub point: TestPoint,
    pub reached: tokio::sync::Notify,
    pub resume: tokio::sync::Semaphore,
}

#[cfg(test)]
impl TestGate {
    pub fn new(point: TestPoint) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { point, reached: tokio::sync::Notify::new(), resume: tokio::sync::Semaphore::new(0) })
    }

    pub async fn pause(&self, point: TestPoint) {
        if self.point == point {
            self.reached.notify_one();
            self.resume.acquire().await.unwrap().forget();
        }
    }
}

/// 无 ID 的旧客户端也必须命中已采用归因的 slot；历史数据不伪造归因。
pub(crate) fn valid_delivery(
    record: &FeedbackEventRecord,
    body: Option<&str>,
    legacy_limit: Option<i64>,
    trusted_legacy_fixture: bool,
) -> Result<bool, sqlx::Error> {
    if record.session_id == "preview:non-learning" {
        return Ok(false);
    }
    let issued = record.application.as_ref().and_then(|a| a.issued_delivery.as_ref());
    let Some(body) = body else {
        return Ok(record.event.delivery_id.is_none()
            && issued.is_none()
            && legacy_limit.map_or(trusted_legacy_fixture, |limit| limit >= 0 && record.event.slot < limit as u64));
    };
    let delivery: memoswish_core::repo::DeliveryRecord =
        serde_json::from_str(body).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    Ok(delivery.card_id == record.event.card_id
        && record.event.delivery_id.as_ref().is_none_or(|id| id == &delivery.attribution.delivery_id)
        && issued == Some(&delivery.attribution))
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn pre_s12_payload_hash_is_unchanged() {
        let batch = memoswish_protocol::examples::sample_feedback_batch();
        let mut event = batch.events[0].clone();
        // 固定值取自 S12 基线的旧字段顺序，新增空字段不能改变既有身份。
        assert_eq!(
            payload_hash(&batch.session_id, &event).unwrap(),
            "07541b28fd0b879e6f9c5115de173a3db47bc97001b658f9ffb034e7afadc5d8"
        );
        event.swipe_velocity = -0.0;
        let negative = payload_hash(&batch.session_id, &event).unwrap();
        event.swipe_velocity = 0.0;
        assert_eq!(payload_hash(&batch.session_id, &event).unwrap(), negative);
        event.delivery_id = Some("dlv-different".into());
        assert_ne!(payload_hash(&batch.session_id, &event).unwrap(), negative);
    }
}
