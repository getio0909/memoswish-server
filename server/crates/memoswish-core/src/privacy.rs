//! 隐私状态转换及服务端准入；调用方配置不能替代用户证据。
use crate::{CoreError, CoreResult, Principal};
use async_trait::async_trait;
use memoswish_protocol::{PrivacyPolicy, PrivacyRecord, PrivacyState, PrivacyUpdate};

pub const PURPOSES: &[&str] = &["external_ai", "external_tts", "diagnostics", "research"];

pub fn validate_policy(policy: &PrivacyPolicy) -> CoreResult<()> {
    if policy.hosted
        && (policy.notice_version.is_empty()
            || policy.terms_version.is_empty()
            || !policy.privacy_url.starts_with("https://")
            || !policy.terms_url.starts_with("https://")
            || policy.allowed_regions.is_empty())
    {
        return Err(CoreError::invalid("hosted privacy policy requires versions, HTTPS links and selected regions"));
    }
    if policy.purpose_versions.iter().any(|(k, v)| !PURPOSES.contains(&k.as_str()) || v.is_empty() || v.len() > 128) {
        return Err(CoreError::invalid("invalid purpose policy"));
    }
    Ok(())
}

pub fn require_collection(state: &PrivacyState, policy: &PrivacyPolicy) -> CoreResult<()> {
    let has = |kind: &str, version: &str| {
        state.account_records.iter().any(|r| r.kind == kind && r.version == version && r.decision)
    };
    let adult = state.account_records.iter().any(|r| {
        r.kind == "age" && r.version == policy.notice_version && r.decision && policy.allowed_regions.contains(&r.value)
    });
    if !has("notice", &policy.notice_version) || !has("terms", &policy.terms_version) || !adult {
        return Err(CoreError::Forbidden("current notice, terms and adult region eligibility required".into()));
    }
    Ok(())
}

pub fn require_purpose(state: &PrivacyState, policy: &PrivacyPolicy, purpose: &str) -> CoreResult<()> {
    require_collection(state, policy)?;
    let version =
        policy.purpose_versions.get(purpose).ok_or_else(|| CoreError::Forbidden("purpose is not configured".into()))?;
    if !state.purpose_records.iter().any(|r| r.kind == purpose && r.version == *version && r.decision) {
        return Err(CoreError::Forbidden("current purpose grant required".into()));
    }
    Ok(())
}

pub fn transition(
    state: &mut PrivacyState,
    policy: &PrivacyPolicy,
    update: &PrivacyUpdate,
    now: i64,
) -> CoreResult<()> {
    let purpose = PURPOSES.contains(&update.kind.as_str());
    let expected = match update.kind.as_str() {
        "notice" | "age" => &policy.notice_version,
        "terms" => &policy.terms_version,
        _ if purpose && !update.decision => &update.version,
        k if purpose => policy.purpose_versions.get(k).ok_or_else(|| CoreError::invalid("unknown purpose policy"))?,
        _ => return Err(CoreError::invalid("unknown privacy record kind")),
    };
    // 撤回不要求重新接受新通知；已撤回的同版本重试保持原时间和修订。
    if purpose
        && !update.decision
        && state.purpose_records.iter().any(|r| r.kind == update.kind && !r.decision && r.version == update.version)
    {
        return Ok(());
    }
    if state.revision != update.expected_revision {
        return Err(CoreError::Conflict("privacy revision changed".into()));
    }
    if update.version.is_empty()
        || update.version.len() > 128
        || (update.decision && update.version != *expected)
        || (!purpose && update.version != *expected)
        || update.value.len() > 64
    {
        return Err(CoreError::invalid("unknown privacy version or invalid value"));
    }
    if update.kind == "age" {
        if !matches!(update.value.as_str(), "unknown" | "underage") && !policy.allowed_regions.contains(&update.value) {
            return Err(CoreError::Forbidden("region is not supported".into()));
        }
        if update.decision && matches!(update.value.as_str(), "unknown" | "underage") {
            return Err(CoreError::invalid("unknown or underage cannot assert adult eligibility"));
        }
    } else if !update.value.is_empty() {
        return Err(CoreError::invalid("unexpected privacy value"));
    }
    if purpose && update.decision {
        require_collection(state, policy)?;
    }
    let records = if purpose { &mut state.purpose_records } else { &mut state.account_records };
    records.retain(|r| r.kind != update.kind);
    records.push(PrivacyRecord {
        kind: update.kind.clone(),
        version: update.version.clone(),
        decision: update.decision,
        value: update.value.clone(),
        recorded_at: now,
        evidence: "self_assertion".into(),
    });
    records.sort_by(|a, b| a.kind.cmp(&b.kind));
    state.revision =
        state.revision.checked_add(1).ok_or_else(|| CoreError::Conflict("privacy revision exhausted".into()))?;
    Ok(())
}

#[async_trait]
pub trait PrivacyRepo: Send + Sync {
    async fn privacy_install_policy(&self, policy: &PrivacyPolicy) -> CoreResult<()>;
    async fn privacy_state(&self, tenant_id: &str, principal: &Principal) -> CoreResult<PrivacyState>;
    async fn privacy_update(
        &self,
        tenant_id: &str,
        principal: &Principal,
        policy: &PrivacyPolicy,
        update: &PrivacyUpdate,
    ) -> CoreResult<PrivacyState>;
    /// 与撤回及凭据撤销串行；返回修订是已准入尝试的发布屏障。
    async fn privacy_admit(
        &self,
        tenant_id: &str,
        principal: &Principal,
        policy: &PrivacyPolicy,
        purpose: Option<&str>,
        admitted_revision: Option<i64>,
    ) -> CoreResult<i64>;
}

/// 持久工作只保存原始凭据摘要，绝不持有 bearer 或补读新代际。
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PrivacyFence {
    pub credential_hash: Option<String>,
    pub principal: Principal,
    pub policy: PrivacyPolicy,
    pub revision: i64,
}
