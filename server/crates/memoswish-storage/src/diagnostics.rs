//! 复用注册锁，与成员、会话撤销、同意撤回和容量检查串行。
macro_rules! diagnostics_impl {
    ($repo:ty, $db:ty) => {
        impl $repo {
            async fn diagnostic_authorize_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, p: &memoswish_core::Principal, policy: &memoswish_protocol::PrivacyPolicy, report: &memoswish_protocol::DiagnosticReport) -> memoswish_core::CoreResult<()> {
                use memoswish_core::{CoreError, privacy::require_purpose};
                memoswish_core::lifecycle::require_first_party(p)?;
                Self::privacy_authorize_tx(tx, tenant, p).await?;
                Self::privacy_policy_tx(tx, policy).await?;
                let state = Self::privacy_read_tx(tx, tenant, &p.user_id).await?;
                require_purpose(&state, policy, "diagnostics")?;
                if state.revision != report.privacy_revision || policy.purpose_versions.get("diagnostics") != Some(&report.purpose_version) {
                    return Err(CoreError::Forbidden("diagnostic authority changed".into()));
                }
                Ok(())
            }
        }
        #[async_trait::async_trait]
        impl memoswish_core::diagnostics::DiagnosticRepo for $repo {
            async fn diagnostic_receive(&self, tenant: &str, p: &memoswish_core::Principal, policy: &memoswish_protocol::PrivacyPolicy, report: &memoswish_protocol::DiagnosticReport, allow_forwarding:bool) -> memoswish_core::CoreResult<memoswish_protocol::DiagnosticReceipt> {
                use memoswish_core::{CoreError, diagnostics::*};
                validate(report)?;
                let body = serde_json::to_string(report).map_err(CoreError::internal)?;
                #[cfg(test)]
                if let Some(gate)=&self.learning_gate {gate.pause(crate::learning::TestPoint::BeforeTransaction).await;}
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                let now = Self::asset_now(&mut tx).await?;
                Self::diagnostic_authorize_tx(&mut tx, tenant, p, policy, report).await?;
                if report.captured_at_ms > now || report.captured_at_ms <= now - RETENTION_MS { return Err(CoreError::invalid("diagnostic capture time is outside retention window")); }
                // 全安装最多一万行，过期清理因此同样有界。
                sqlx::query(&format!("DELETE FROM diagnostic_reports WHERE (tenant_id,user_id,report_id) IN (SELECT tenant_id,user_id,report_id FROM ({}) candidates)",crate::recovery::DIAGNOSTIC_EXPIRY.at("$1"))).bind(now).execute(&mut *tx).await.map_err(db_err)?;
                let existing: Option<String> = sqlx::query_scalar("SELECT body FROM diagnostic_reports WHERE tenant_id=$1 AND user_id=$2 AND report_id=$3")
                    .bind(tenant).bind(&p.user_id).bind(&report.report_id).fetch_optional(&mut *tx).await.map_err(db_err)?;
                let duplicate = if let Some(existing) = existing {
                    if existing != body { return Err(CoreError::Conflict("diagnostic identity has different content".into())); }
                    true
                } else {
                    let subject: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_reports WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant).bind(&p.user_id).fetch_one(&mut *tx).await.map_err(db_err)?;
                    let all: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_reports").fetch_one(&mut *tx).await.map_err(db_err)?;
                    if subject >= SUBJECT_CAP || all >= INSTALLATION_CAP { return Err(CoreError::Conflict("diagnostic inbox capacity reached".into())); }
                    sqlx::query("INSERT INTO diagnostic_reports(tenant_id,user_id,report_id,body,privacy_revision,created_at_ms,expires_at_ms,forward_authority) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                        .bind(tenant).bind(&p.user_id).bind(&report.report_id).bind(body).bind(report.privacy_revision).bind(now).bind(report.captured_at_ms + RETENTION_MS)
                        .bind(if allow_forwarding { Some(serde_json::to_string(&memoswish_core::privacy::PrivacyFence { principal:p.clone(),credential_hash:p.session_access_hash.clone(),policy:policy.clone(),revision:report.privacy_revision }).map_err(CoreError::internal)?) } else {None})
                        .execute(&mut *tx).await.map_err(db_err)?;
                    false
                };
                #[cfg(test)]
                if let Some(gate)=&self.learning_gate {gate.pause(crate::learning::TestPoint::BeforeCommit).await;}
                tx.commit().await.map_err(db_err)?;
                Ok(memoswish_protocol::DiagnosticReceipt { report_id: report.report_id.clone(), duplicate })
            }
            async fn diagnostic_recovery(
                &self,
                admission: &memoswish_core::maintenance::MaintenanceAdmission,
            ) -> memoswish_core::CoreResult<Option<(memoswish_core::Principal, memoswish_protocol::DiagnosticReport)>> {
                use memoswish_core::{CoreError, maintenance::TaskKind};
                if admission.kind != TaskKind::DiagnosticRecovery {
                    return Err(CoreError::invalid("invalid diagnostic admission kind"));
                }
                // 回执与作用域逐字段核验；不从当前身份补读原始授权。
                let row:Option<(String,String)>=sqlx::query_as("SELECT d.forward_authority,d.body FROM diagnostic_reports d JOIN maintenance_admissions a ON a.tenant_id=d.tenant_id AND a.item_id=d.user_id || ':' || d.report_id JOIN maintenance_tasks m ON m.id=a.task_id WHERE a.admission_id=$1 AND a.tenant_id=$2 AND a.item_id=$3 AND m.task_kind='diagnostic_recovery' AND d.dispatch_started=0 AND d.forward_authority IS NOT NULL")
                    .bind(&admission.admission_id).bind(&admission.item.tenant).bind(&admission.item.id).fetch_optional(&self.pool).await.map_err(db_err)?;
                let Some((authority, body)) = row else { return Ok(None) };
                let fence: memoswish_core::privacy::PrivacyFence = serde_json::from_str(&authority)
                    .map_err(|_| CoreError::internal("invalid diagnostic authority"))?;
                let report: memoswish_protocol::DiagnosticReport = serde_json::from_str(&body)
                    .map_err(|_| CoreError::internal("invalid diagnostic report"))?;
                let mut principal = fence.principal;
                principal.session_access_hash = fence.credential_hash;
                Ok(Some((principal, report)))
            }
            async fn diagnostic_dispatch(&self, tenant: &str, p: &memoswish_core::Principal, policy: &memoswish_protocol::PrivacyPolicy, report: &memoswish_protocol::DiagnosticReport) -> memoswish_core::CoreResult<bool> {
                memoswish_core::diagnostics::validate(report)?;
                let body = serde_json::to_string(report).map_err(memoswish_core::CoreError::internal)?;
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                let now = Self::asset_now(&mut tx).await?;
                Self::diagnostic_authorize_tx(&mut tx, tenant, p, policy, report).await?;
                let changed = sqlx::query("UPDATE diagnostic_reports SET dispatch_started=1,forward_authority=NULL WHERE tenant_id=$1 AND user_id=$2 AND report_id=$3 AND body=$4 AND dispatch_started=0 AND expires_at_ms>$5")
                    .bind(tenant).bind(&p.user_id).bind(&report.report_id).bind(body).bind(now).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                tx.commit().await.map_err(db_err)?;
                Ok(changed == 1)
            }
        }
    };
}
pub(crate) use diagnostics_impl;
