//! 解释的保守预算、持久处置与最小财务证据；不依赖商业配额。
use crate::{CoreError, CoreResult, Principal};
use async_trait::async_trait;
use memoswish_protocol::{CardExplanation, ExplainOperation};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationPolicy {
    pub deployment_id: String,
    pub provider_account: String,
    pub pricing_version: String,
    pub currency: String,
    pub valid_until_ms: i64,
    pub input_rate: i64,
    pub output_rate: i64,
    pub rate_denominator: i64,
    pub tenant_limit: i64,
    pub deployment_limit: i64,
    pub provider_limit: i64,
    pub unresolved_limit: i64,
    pub cache_entry_bytes: i64,
    pub cache_tenant_bytes: i64,
    pub cache_deployment_bytes: i64,
    pub cache_ttl_ms: i64,
}
impl std::fmt::Debug for ExplanationPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplanationPolicy").finish_non_exhaustive()
    }
}
impl ExplanationPolicy {
    pub fn validate(&self, now: i64) -> CoreResult<()> {
        for id in [&self.deployment_id, &self.provider_account, &self.pricing_version] {
            validate_id(id)?;
        }
        if self.currency.len() != 3
            || !self.currency.bytes().all(|c| c.is_ascii_uppercase())
            || self.valid_until_ms <= now
            || self.input_rate <= 0
            || self.output_rate <= 0
            || self.rate_denominator <= 0
            || [self.tenant_limit, self.deployment_limit, self.provider_limit, self.unresolved_limit]
                .iter()
                .any(|v| *v <= 0)
            || !(1..=16_384).contains(&self.cache_entry_bytes)
            || self.cache_tenant_bytes < self.cache_entry_bytes
            || self.cache_deployment_bytes < self.cache_tenant_bytes
            || !(1..=86_400_000).contains(&self.cache_ttl_ms)
        {
            return Err(CoreError::invalid("invalid or expired explanation policy"));
        }
        self.cost(128_000, 1024)?;
        Ok(())
    }
    pub fn cost(&self, input: i64, output: i64) -> CoreResult<i64> {
        let invalid = || CoreError::invalid("explanation cost is invalid or overflows");
        if input < 0 || output < 0 || self.input_rate <= 0 || self.output_rate <= 0 || self.rate_denominator <= 0 {
            return Err(invalid());
        }
        let ceil = |tokens: i64, rate: i64| -> i128 {
            let n = i128::from(tokens) * i128::from(rate);
            (n + i128::from(self.rate_denominator) - 1) / i128::from(self.rate_denominator)
        };
        i64::try_from(ceil(input, self.input_rate) + ceil(output, self.output_rate)).map_err(|_| invalid())
    }
}

pub fn validate_id(id: &str) -> CoreResult<()> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c)) {
        return Err(CoreError::invalid("explanation identity must be 1..=128 safe ASCII bytes"));
    }
    Ok(())
}

/// 已捕获的非秘密版本上下文；原始正文只保留命令摘要。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplanationContext {
    pub locale: String,
    pub model_profile: String,
    pub prompt_version: String,
    pub policy_version: String,
}
impl std::fmt::Debug for ExplanationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplanationContext").finish_non_exhaustive()
    }
}
impl ExplanationContext {
    pub fn validate(&self) -> CoreResult<()> {
        if self.locale.is_empty()
            || self.locale.len() > 35
            || !self.locale.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(CoreError::invalid("invalid captured explanation locale"));
        }
        for value in [&self.model_profile, &self.prompt_version, &self.policy_version] {
            validate_id(value)?;
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct ExplanationAdmission {
    pub context: ExplanationContext,
    pub request_id: String,
    pub command_hash: String,
    pub card_id: String,
    pub revision: u32,
    pub cache_key: Option<String>,
    pub profile_id: String,
    pub policy: Option<ExplanationPolicy>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplanationUsage {
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// 仅持久化已验证的数字和摘要，不持久化提供者正文或任意错误。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExplanationEvidence {
    Usage(ExplanationUsage),
    NotCharged { reference_sha256: String },
}

#[derive(Clone)]
pub struct ExplanationRecord {
    pub id: String,
    pub configuration_id: String,
    pub operation: ExplainOperation,
    pub result: Option<CardExplanation>,
}

/// 用户操作带显式租户主体；维护扫描与财务结算是窄内部入口。
#[async_trait]
pub trait ExplanationRepo: Send + Sync {
    async fn admit_explanation(&self, p: &Principal, request: &ExplanationAdmission) -> CoreResult<ExplanationRecord>;
    async fn lookup_explanation(
        &self,
        p: &Principal,
        request_id: &str,
        command: Option<&str>,
    ) -> CoreResult<Option<ExplanationRecord>>;
    async fn suppress_explanation(&self, p: &Principal, request_id: &str) -> CoreResult<()>;
    async fn begin_explanation_attempt(&self, p: &Principal, id: &str) -> CoreResult<bool>;
    async fn settle_explanation(&self, tenant_id: &str, id: &str, evidence: &ExplanationEvidence) -> CoreResult<()>;
    async fn publish_explanation(&self, p: &Principal, id: &str, result: &CardExplanation) -> CoreResult<bool>;
    /// 当前账务权限只结算同租户同主体的请求，不恢复原执行或正文读取权限。
    async fn reconcile_explanation(
        &self,
        p: &Principal,
        request_id: &str,
        evidence: &ExplanationEvidence,
    ) -> CoreResult<ExplainOperation>;
    async fn maintain_explanations(&self, after: Option<(&str, &str)>) -> CoreResult<Vec<(String, String)>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conservative_cost_rounds_each_dimension_and_rejects_invalid_arithmetic() {
        let mut p = ExplanationPolicy {
            deployment_id: "d".into(),
            provider_account: "p".into(),
            pricing_version: "v1".into(),
            currency: "USD".into(),
            valid_until_ms: 100,
            input_rate: 1,
            output_rate: 1,
            rate_denominator: 3,
            tenant_limit: 10,
            deployment_limit: 10,
            provider_limit: 10,
            unresolved_limit: 10,
            cache_entry_bytes: 100,
            cache_tenant_bytes: 100,
            cache_deployment_bytes: 100,
            cache_ttl_ms: 100,
        };
        assert_eq!(p.cost(1, 1).unwrap(), 2);
        assert!(p.cost(-1, 1).is_err());
        p.input_rate = i64::MAX;
        assert!(p.cost(i64::MAX, 1).is_err());
        p.rate_denominator = 0;
        assert!(p.cost(0, 0).is_err());
        p.rate_denominator = 1;
        p.input_rate = 1;
        assert!(p.validate(100).is_err());
        p.valid_until_ms = 101;
        p.tenant_limit = 0;
        assert!(p.validate(100).is_err());
    }
}
