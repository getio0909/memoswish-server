//! 请求取消后仍由 OperationTracker 持有；重放只读原责任，绝不重发。
use crate::Services;
use memoswish_content::explain::*;
use memoswish_core::{CoreError, CoreResult, Principal, explanations::*};
use memoswish_protocol::{CardExplanation, ExplainDisposition, ExplainOperation, ExplainRequest};

impl Services {
    pub async fn reconcile_explanation_request(
        &self,
        p: &Principal,
        key: &str,
        request: &memoswish_protocol::ExplainReconcileRequest,
    ) -> CoreResult<ExplainOperation> {
        p.require(memoswish_core::Permission::BillingManage)?;
        if !self.media.executes_work() {
            return Err(CoreError::Unavailable("explanation settlement is not available in this role".into()));
        }
        let evidence = match (request.input_tokens, request.output_tokens, &request.not_charged_reference_sha256) {
            (Some(input_tokens), Some(output_tokens), None) if input_tokens >= 0 && output_tokens >= 0 => {
                ExplanationEvidence::Usage(ExplanationUsage { input_tokens, output_tokens })
            }
            (None, None, Some(reference_sha256)) => {
                ExplanationEvidence::NotCharged { reference_sha256: reference_sha256.clone() }
            }
            _ => return Err(CoreError::invalid("provide usage or affirmative no-charge evidence, exclusively")),
        };
        let services = self.clone();
        let p = p.clone();
        let key = key.to_owned();
        // 核账与自动结算共享关闭准入和任务归属，传输取消不能丢弃已接收的财务写入。
        self.operations
            .spawn(async move {
                services.content.explanation_repository().reconcile_explanation(&p, &key, &evidence).await
            })?
            .await
            .map_err(|_| {
                CoreError::Unavailable(
                    "explanation settlement owner interrupted; look up original request identity".into(),
                )
            })?
    }

    pub(super) async fn explain_request(
        &self,
        p: &Principal,
        card_id: &str,
        request: &ExplainRequest,
    ) -> CoreResult<CardExplanation> {
        let Some(key) = request.request_id.as_deref() else {
            // 旧客户端缺持久身份时保留本地功能，不生成一次性付费身份。
            return self.content.explain_card(p, card_id, request).await;
        };
        validate_id(key)?;
        let services = self.clone();
        let p = p.clone();
        let card_id = card_id.to_string();
        let request = request.clone();
        self.operations.spawn(async move { services.explain_owned(&p, &card_id, &request).await })?.await.map_err(
            |_| CoreError::Unavailable("explanation owner interrupted; look up original request identity".into()),
        )?
    }
    async fn explain_owned(
        &self,
        p: &Principal,
        card_id: &str,
        request: &ExplainRequest,
    ) -> CoreResult<CardExplanation> {
        let control = crate::OperationControl::current();
        control.checkpoint()?;
        let key = request.request_id.as_deref().unwrap();
        // 原始命令在解析可变默认值前绑定，不把当前配置写入调用身份。
        let command = memoswish_core::ids::sha256_hex(
            &serde_json::to_vec(&(card_id, &request.question, &request.locale))
                .map_err(|_| CoreError::invalid("invalid explanation command"))?,
        );
        let repo = self.content.explanation_repository();
        let existing = repo.lookup_explanation(p, key, Some(&command)).await?;
        let card = self.content.get_card(p, card_id).await?;
        validate_input(&card, request)?;
        let mut effective = request.clone();
        if effective.locale.is_none() {
            effective.locale = Some(card.language.clone());
        }
        validate_input(&card, &effective)?;
        let cfg = self.content.explanation_config();
        let profile_id = explanation_profile_id(cfg)?;
        let policy = cfg
            .budget
            .as_ref()
            .filter(|policy| {
                external_profile_supported(cfg)
                    && policy
                        .validate(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|v| v.as_millis() as i64)
                                .unwrap_or(i64::MAX),
                        )
                        .is_ok()
            })
            .cloned();
        if policy.is_some() {
            if !self.media.executes_work() {
                return Err(CoreError::Unavailable(
                    "external explanation execution is not available in this role".into(),
                ));
            }
            if existing.is_none() {
                self.auth.admit_privacy_purpose(p, "external_ai", None).await?;
            }
        }
        let context = ExplanationContext {
            locale: effective.locale.clone().unwrap_or_else(|| card.language.clone()),
            model_profile: if matches!(cfg.model.as_str(), DEFAULT_AI_MODEL | "gpt-4o-mini-2024-07-18") {
                cfg.model.clone()
            } else if external_profile_supported(cfg) {
                // 配置模型可含路径或敏感值，只捕获已验证格式的配置摘要。
                profile_id.clone()
            } else {
                BUILTIN_PROVIDER.into()
            },
            prompt_version: "explain-prompt-v1".into(),
            policy_version: "purpose-admission-v1".into(),
        };
        let cache_key = if request.question.is_none() {
            Some(memoswish_core::ids::sha256_hex(
                &serde_json::to_vec(&(&p.tenant_id, &p.user_id, &card.id, card.revision, &context, &profile_id))
                    .map_err(|_| CoreError::internal("invalid explanation cache identity"))?,
            ))
        } else {
            None
        };
        let mut admission = ExplanationAdmission {
            context,
            request_id: key.into(),
            command_hash: command,
            card_id: card.id.clone(),
            revision: card.revision,
            cache_key,
            profile_id,
            policy,
        };
        let record = match existing {
            Some(record) => record,
            None => {
                control.begin_acceptance()?;
                match repo.admit_explanation(p, &admission).await {
                    Ok(record) => record,
                    Err(CoreError::QuotaExceeded(_)) => {
                        admission.policy = None;
                        control.begin_acceptance()?;
                        repo.admit_explanation(p, &admission).await?
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        control.accepted();
        if admission.policy.is_some()
            && record.configuration_id == admission.profile_id
            && record.operation.disposition == ExplainDisposition::Pending
            && repo.begin_explanation_attempt(p, key).await?
        {
            let outcome = execute_admitted_explanation_observed(
                &card,
                &effective,
                cfg,
                &record.id,
                self.content.explanation_observer(),
            )
            .await?;
            if let Some(usage) = outcome.usage {
                repo.settle_explanation(&p.tenant_id, &record.id, &ExplanationEvidence::Usage(usage)).await?;
                if let Ok(explanation) = outcome.explanation {
                    // 发布失败不撤销财务事实；返回前再读取当前授权与内容版本。
                    let _ = repo.publish_explanation(p, key, &explanation).await?;
                }
            }
        }
        let current = repo
            .lookup_explanation(p, key, Some(&admission.command_hash))
            .await?
            .ok_or_else(|| CoreError::NotFound("explanation request".into()))?;
        if current.operation.disposition == ExplainDisposition::Suppressed {
            return Err(CoreError::Forbidden("explanation publication is no longer eligible".into()));
        }
        let mut result = current.result.unwrap_or_else(|| heuristic_explain(&card, &effective));
        result.operation = Some(current.operation);
        if validate_result(&result).is_err() {
            let mut fallback = heuristic_explain(&card, &effective);
            fallback.operation = result.operation;
            result = fallback;
        }
        validate_result(&result)?;
        Ok(result)
    }
    pub async fn explanation_operation(&self, p: &Principal, key: &str) -> CoreResult<ExplainOperation> {
        self.content
            .explanation_repository()
            .lookup_explanation(p, key, None)
            .await?
            .map(|r| r.operation)
            .ok_or_else(|| CoreError::NotFound("explanation request".into()))
    }
    /// 有界维护仅取消尚未尝试的责任并删除过期文本，未知费用仍保留。
    pub fn recover_explanations(&self) -> CoreResult<tokio::task::JoinHandle<CoreResult<()>>> {
        if !self.media.executes_work() {
            return Err(CoreError::Unavailable("explanation recovery is not available in this role".into()));
        }
        self.recover_scheduled(memoswish_core::maintenance::TaskKind::ExplanationRecovery)
    }
}
