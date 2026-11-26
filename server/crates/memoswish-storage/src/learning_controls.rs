//! 双库共享学习控制事务；复用生命周期锁和凭据屏障，不引入后台任务。
macro_rules! learning_controls_impl {
    ($repo:ty, $db:ty) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Permission, Principal};
            use memoswish_core::learning_controls::{LearningControlsRepo, validate_retention};
            use memoswish_protocol::*;
            use sqlx::Row;
            use crate::feed_issuance::db_error;

            impl $repo {
                async fn controls_tx(&self, tenant: &str, p: &Principal, write: bool) -> CoreResult<sqlx::Transaction<'_, $db>> {
                    if tenant != p.tenant_id { return Err(CoreError::Forbidden("learner tenant mismatch".into())); }
                    let permission = if write { Permission::FeedbackWrite } else { Permission::FeedRead };
                    p.require(permission)?;
                    let mut tx = self.learning_write_tx(tenant, &p.user_id, Some(p.credential_generations()?)).await?;
                    Self::learning_principal_tx(&mut tx, p).await?;
                    let role = Self::authorize_tx(&mut tx, tenant, &p.user_id, p.credential_generations()?).await?;
                    if !role.allows(permission) { return Err(CoreError::Forbidden("current role cannot use learner controls".into())); }
                    if !Self::credential_current(&mut tx, p, &[permission]).await? { return Err(CoreError::Unauthorized("learner credential was revoked".into())); }
                    if write { Self::privacy_collection_tx(&mut tx, tenant, &p.user_id).await?; }
                    Ok(tx)
                }
                async fn controls_preferences_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str, default: f64) -> CoreResult<LearnerPreferences> {
                    let row = sqlx::query("SELECT revision,desired_retention FROM learner_preferences WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant).bind(user).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let (revision, desired_retention) = row.map_or((0,None), |r| (r.get("revision"), r.get("desired_retention")));
                    Ok(LearnerPreferences { revision, desired_retention, effective_retention: desired_retention.unwrap_or(default) })
                }
                pub(crate) async fn controls_card_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str, card: &str) -> CoreResult<LearnerCardControl> {
                    if sqlx::query("SELECT id FROM cards WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(card).fetch_optional(&mut **tx).await.map_err(db_error)?.is_none() {
                        return Err(CoreError::NotFound("card".into()));
                    }
                    let row = sqlx::query("SELECT revision,suspended,buried_until_ms FROM learner_card_controls WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3")
                        .bind(tenant).bind(user).bind(card).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let (revision,suspended,buried) = row.map_or((0,false,None), |r| (r.get("revision"),r.get::<i64,_>("suspended")!=0,r.get::<Option<i64>,_>("buried_until_ms")));
                    Ok(LearnerCardControl {card_id:card.into(),revision,suspended,buried_until:buried.map(|v| chrono::DateTime::from_timestamp_millis(v).ok_or_else(|| CoreError::internal("invalid burial deadline"))).transpose()?})
                }
                async fn controls_bump_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str) -> CoreResult<()> {
                    sqlx::query("INSERT INTO learner_preferences(tenant_id,user_id,epoch) VALUES($1,$2,1) ON CONFLICT(tenant_id,user_id) DO UPDATE SET epoch=learner_preferences.epoch+1")
                        .bind(tenant).bind(user).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
            }
            #[async_trait::async_trait]
            impl LearningControlsRepo for $repo {
                async fn learner_preferences(&self, tenant: &str, p: &Principal, default: f64) -> CoreResult<LearnerPreferences> {
                    validate_retention(Some(default))?;
                    let mut tx=self.controls_tx(tenant,p,false).await?;
                    Self::controls_preferences_tx(&mut tx,tenant,&p.user_id,default).await
                }
                async fn set_retention(&self, tenant: &str, p: &Principal, command: &RetentionCommand, default: f64) -> CoreResult<LearnerPreferences> {
                    validate_retention(Some(default))?;
                    validate_retention(command.desired_retention.flatten())?;
                    let mut tx=self.controls_tx(tenant,p,true).await?;
                    let old=Self::controls_preferences_tx(&mut tx,tenant,&p.user_id,default).await?;
                    if old.revision != command.expected_revision { return Err(CoreError::Conflict("learner preference revision changed; reload before editing".into())); }
                    // 无字段命令仍执行授权与 CAS，但不修改修订或发卡世代。
                    let Some(desired_retention) = command.desired_retention else { return Ok(old); };
                    let next=old.revision.checked_add(1).ok_or_else(|| CoreError::Conflict("learner preference revision exhausted".into()))?;
                    Self::controls_bump_tx(&mut tx,tenant,&p.user_id).await?;
                    sqlx::query("UPDATE learner_preferences SET desired_retention=$3,revision=$4 WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant).bind(&p.user_id).bind(desired_retention).bind(next).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(LearnerPreferences {revision:next,desired_retention,effective_retention:desired_retention.unwrap_or(default)})
                }
                async fn card_control(&self, tenant: &str, p: &Principal, card: &str) -> CoreResult<LearnerCardControl> {
                    let mut tx=self.controls_tx(tenant,p,false).await?;
                    Self::controls_card_tx(&mut tx,tenant,&p.user_id,card).await
                }
                async fn set_card_control(&self, tenant: &str, p: &Principal, card: &str, command: &CardControlCommand) -> CoreResult<LearnerCardControl> {
                    let mut tx=self.controls_tx(tenant,p,true).await?;
                    let mut control=Self::controls_card_tx(&mut tx,tenant,&p.user_id,card).await?;
                    if control.revision!=command.expected_revision { return Err(CoreError::Conflict("card control revision changed; reload before editing".into())); }
                    control.revision=control.revision.checked_add(1).ok_or_else(|| CoreError::Conflict("card control revision exhausted".into()))?;
                    control.buried_until=match command.action {
                        CardControlAction::Suspend => { control.suspended=true; None },
                        CardControlAction::Resume => { control.suspended=false; None },
                        CardControlAction::Bury => {
                            if control.suspended { return Err(CoreError::Conflict("resume a suspended card before burying".into())); }
                            let now=Self::asset_now(&mut tx).await?;
                            Some(chrono::DateTime::from_timestamp_millis(now).ok_or_else(|| CoreError::internal("invalid database clock"))? + chrono::Duration::hours(24))
                        }
                    };
                    Self::controls_bump_tx(&mut tx,tenant,&p.user_id).await?;
                    sqlx::query("INSERT INTO learner_card_controls(tenant_id,user_id,card_id,revision,suspended,buried_until_ms) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,user_id,card_id) DO UPDATE SET revision=excluded.revision,suspended=excluded.suspended,buried_until_ms=excluded.buried_until_ms")
                        .bind(tenant).bind(&p.user_id).bind(card).bind(control.revision).bind(i64::from(control.suspended)).bind(control.buried_until.map(|v|v.timestamp_millis()))
                        .execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(control)
                }
                async fn hidden_cards(&self, tenant: &str, p: &Principal, after: Option<&str>, limit: u32) -> CoreResult<HiddenCardsPage> {
                    if after.is_some_and(|v|v.len()>256) { return Err(CoreError::invalid("invalid hidden-card cursor")); }
                    let mut tx=self.controls_tx(tenant,p,false).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    let limit=i64::from(limit.clamp(1,100));
                    let rows=sqlx::query("SELECT card_id,revision,suspended,buried_until_ms FROM learner_card_controls WHERE tenant_id=$1 AND user_id=$2 AND card_id>$3 AND (suspended=1 OR buried_until_ms>$4) ORDER BY card_id LIMIT $5")
                        .bind(tenant).bind(&p.user_id).bind(after.unwrap_or("")).bind(now).bind(limit+1).fetch_all(&mut *tx).await.map_err(db_error)?;
                    let has_more=rows.len()>limit as usize;
                    let items=rows.into_iter().take(limit as usize).map(|r| {
                        let buried:Option<i64>=r.get("buried_until_ms");
                        Ok(LearnerCardControl { card_id:r.get("card_id"),revision:r.get("revision"),suspended:r.get::<i64,_>("suspended")!=0,buried_until:buried.map(|v|chrono::DateTime::from_timestamp_millis(v).ok_or_else(||CoreError::internal("invalid burial deadline"))).transpose()? })
                    }).collect::<CoreResult<Vec<_>>>()?;
                    let next_after=if has_more {items.last().map(|c|c.card_id.clone())} else {None};
                    Ok(HiddenCardsPage {items,next_after})
                }
            }
        };
    };
}
pub(crate) use learning_controls_impl;
