//! 解释的双库事务：注册锁串行授权、准入、缓存与跨租户账本。
macro_rules! explanations_impl {
    ($repo:ty, $db:ty, $row:ty) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Principal, Permission};
            use memoswish_core::explanations::*;
            use memoswish_core::imports::{ImportAuthority, ImportCredential};
            use memoswish_protocol::{CardExplanation, ExplainOperation, ExplainDisposition};
            use sqlx::{Row, types::Json};
            use crate::assets::db_error;

            impl $repo {
                // 与用途撤回共享注册锁，准入、发送和正文释放均核对原修订。
                pub(crate) async fn explanation_privacy_tx(
                    tx: &mut sqlx::Transaction<'_, $db>,
                    tenant: &str,
                    user: &str,
                    expected: Option<&str>,
                ) -> CoreResult<String> {
                    let body: Option<String> = sqlx::query_scalar("SELECT body FROM privacy_deployment_policy WHERE id=1")
                        .fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let policy: memoswish_protocol::PrivacyPolicy = serde_json::from_str(
                        &body.ok_or_else(|| CoreError::Forbidden("explanation purpose policy is missing".into()))?
                    ).map_err(|_| CoreError::internal("invalid privacy deployment policy"))?;
                    let state = Self::privacy_read_tx(tx, tenant, user).await?;
                    memoswish_core::privacy::require_purpose(&state, &policy, "external_ai")?;
                    let fence = serde_json::to_string(&(policy, state.revision))
                        .map_err(|_| CoreError::internal("invalid explanation privacy fence"))?;
                    if expected.is_some_and(|old| old != fence) {
                        return Err(CoreError::Forbidden("privacy changed after explanation admission".into()));
                    }
                    Ok(fence)
                }
                fn explanation_financial_id(policy:&ExplanationPolicy) -> String {
                    let mut bytes=Vec::new();
                    for id in [&policy.deployment_id,&policy.provider_account,&policy.pricing_version] {bytes.extend_from_slice(&(id.len() as u64).to_be_bytes());bytes.extend_from_slice(id.as_bytes());}
                    memoswish_core::ids::sha256_hex(&bytes)
                }
                fn explanation_authority(p:&Principal) -> ImportAuthority {
                    let token_hash=p.session_access_hash.as_deref().and_then(|v|v.strip_prefix("api:").or_else(||v.strip_prefix("oauth:"))).map(str::to_string);
                    let expires_at=p.session_access_hash.as_deref().and_then(|v|v.strip_prefix("jwt:")).and_then(|v|v.parse().ok());
                    ImportAuthority::capture(p,Some(ImportCredential{token_hash,expires_at}))
                }
                async fn explanation_authorize(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal) -> CoreResult<()> {
                    let token_hash=p.session_access_hash.as_deref().and_then(|v| v.strip_prefix("api:").or_else(||v.strip_prefix("oauth:"))).map(str::to_string);
                    let expires_at=p.session_access_hash.as_deref().and_then(|v|v.strip_prefix("jwt:")).and_then(|v|v.parse().ok());
                    let authority=ImportAuthority::capture(p,Some(ImportCredential{token_hash,expires_at}));
                    Self::content_authorize(tx,&authority,Permission::ContentRead,false).await?;
                    Ok(())
                }
                async fn explanation_card_current(tx: &mut sqlx::Transaction<'_, $db>, tenant:&str, row:&$row) -> CoreResult<bool> {
                    let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM cards WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(row.get::<String,_>("card_id")).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    Ok(revision==Some(row.get("revision")))
                }
                // 事务内复核当前角色与委托范围，避免读取之后撤回或降权仍触发付费请求。
                async fn explanation_card_visible(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, id: &str) -> CoreResult<bool> {
                    let current = Self::content_authorize(tx, &Self::explanation_authority(p), Permission::ContentRead, false).await?;
                    let publication: Option<String> = sqlx::query_scalar("SELECT publication FROM cards WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    Ok(publication.is_some_and(|state| state == "published" || current.can(Permission::ContentWrite)))
                }
                fn explanation_record(row:&$row, request_id:&str, now:i64, eligible:bool) -> CoreResult<ExplanationRecord> {
                    let state:String=row.get("state");
                    let mut disposition:ExplainDisposition=serde_json::from_value(serde_json::Value::String(state)).map_err(|_|CoreError::internal("invalid explanation state"))?;
                    let bytes:Option<String>=row.get("result");
                    let live=eligible && row.get::<i64,_>("expires_at_ms")>now;
                    if !eligible {disposition=ExplainDisposition::Suppressed;}
                    else if !live && bytes.is_some() {disposition=ExplainDisposition::Expired;}
                    let result=if live {bytes.map(|v|serde_json::from_str::<CardExplanation>(&v).map_err(|_|CoreError::internal("invalid explanation result"))).transpose()?} else {None};
                    let operation=Self::explanation_receipt(row,request_id,disposition)?;
                    Ok(ExplanationRecord{id:row.get("id"),configuration_id:row.get("configuration_id"),operation,result})
                }
                // 账务回执不读取或解码正文，不依赖原执行世代与内容存活。
                fn explanation_receipt(row:&$row, request_id:&str, disposition:ExplainDisposition) -> CoreResult<ExplainOperation> {
                    let accounting=if let Some(encoded)=row.get::<Option<String>,_>("policy") {
                        let policy:ExplanationPolicy=serde_json::from_str(&encoded).map_err(|_|CoreError::internal("invalid captured explanation policy"))?;
                        let evidence:Option<ExplanationEvidence>=row.get::<Option<String>,_>("evidence").map(|v|serde_json::from_str(&v).map_err(|_|CoreError::internal("invalid explanation evidence"))).transpose()?;
                        let (input_tokens,output_tokens,committed)=match &evidence {Some(ExplanationEvidence::Usage(u))=>(Some(u.input_tokens),Some(u.output_tokens),policy.cost(u.input_tokens,u.output_tokens)?),_=>(None,None,0)};
                        let held=if evidence.is_none() && (row.get::<i64,_>("attempted")==1 || !matches!(disposition,ExplainDisposition::Cancelled|ExplainDisposition::Suppressed)) {policy.cost(128_000,1024)?}else{0};
                        Some(memoswish_protocol::ExplainAccounting{requests:1,attempts:row.get::<i64,_>("attempted") as u32,period:row.get("period"),currency:policy.currency,held_microcurrency:held,committed_microcurrency:committed,input_tokens,output_tokens})
                    }else{None};
                    Ok(ExplainOperation{accounting,request_id:request_id.into(),disposition})
                }
                async fn explanation_lookup_tx(tx:&mut sqlx::Transaction<'_, $db>,p:&Principal,key:&str,command:Option<&str>) -> CoreResult<Option<ExplanationRecord>> {
                    validate_id(key)?;
                    Self::explanation_authorize(tx,p).await?;
                    let row=sqlx::query("SELECT o.*,r.command_hash FROM explanation_requests r JOIN explanation_operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.request_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(key).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let Some(row)=row else{return Ok(None)};
                    if command.is_some_and(|v|v!=row.get::<String,_>("command_hash")) {return Err(CoreError::Conflict("explanation identity has a different command".into()));}
                    if Some(row.get::<i64,_>("account_generation"))!=p.auth_generation || Some(row.get::<i64,_>("membership_generation"))!=p.membership_generation {return Err(CoreError::Forbidden("explanation owner generation changed".into()));}
                    let plan:String=sqlx::query_scalar("SELECT plan FROM tenants WHERE id=$1").bind(&p.tenant_id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    let paid = row.get::<Option<String>,_>("policy").is_some();
                    let terminal_without_result = matches!(row.get::<String,_>("state").as_str(), "expired" | "cancelled")
                        && row.get::<Option<String>,_>("result").is_none();
                    let privacy_current = if paid && !terminal_without_result {
                        match row.get::<Option<String>,_>("privacy") {
                            Some(fence) => match Self::explanation_privacy_tx(tx, &p.tenant_id, &p.user_id, Some(&fence)).await {
                                Ok(_) => true,
                                Err(CoreError::Forbidden(_)) => false,
                                Err(error) => return Err(error),
                            },
                            None => false,
                        }
                    } else { true };
                    let eligible=Self::explanation_card_current(tx,&p.tenant_id,&row).await?
                        && Self::explanation_card_visible(tx,p,&row.get::<String,_>("card_id")).await?
                        && (!paid || matches!(plan.as_str(), "self_hosted" | "free" | "pro" | "team"))
                        && privacy_current;
                    if !eligible {
                        Self::explanation_suppress_tx(tx, &p.tenant_id, &row.get::<String,_>("id"), row.get("attempted")).await?;
                    }
                    let now=Self::asset_now(tx).await?;
                    Ok(Some(Self::explanation_record(&row,key,now,eligible)?))
                }
                async fn explanation_release(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,id:&str,actual:i64)->CoreResult<()> {
                    let rows=sqlx::query("SELECT scope,period,amount FROM explanation_holds WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(id).fetch_all(&mut **tx).await.map_err(db_error)?;
                    for row in rows {
                        let scope:String=row.get("scope");let period:String=row.get("period");let amount:i64=row.get("amount");
                        let used:i64=sqlx::query_scalar("SELECT committed FROM explanation_accounts WHERE scope=$1 AND period=$2").bind(&scope).bind(&period).fetch_one(&mut **tx).await.map_err(db_error)?;
                        let next=used.checked_add(actual).ok_or_else(||CoreError::invalid("explanation accounting overflow"))?;
                        sqlx::query("UPDATE explanation_accounts SET held=held-$3,committed=$4 WHERE scope=$1 AND period=$2").bind(scope).bind(period).bind(amount).bind(next).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    sqlx::query("DELETE FROM explanation_holds WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
                async fn explanation_settle_tx(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,id:&str,evidence:&ExplanationEvidence)->CoreResult<()> {
                    let row=sqlx::query("SELECT * FROM explanation_operations WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_optional(&mut **tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("explanation operation".into()))?;
                    let encoded=serde_json::to_string(evidence).map_err(|_|CoreError::internal("invalid explanation evidence"))?;
                    if let Some(old)=row.get::<Option<String>,_>("evidence") {
                        if old==encoded {return Ok(())} else {return Err(CoreError::Conflict("explanation evidence already settled".into()))}
                    }
                    if row.get::<i64,_>("attempted")!=1 {return Err(CoreError::Conflict("explanation has no paid attempt".into()));}
                    let policy:ExplanationPolicy=serde_json::from_str(&row.get::<String,_>("policy")).map_err(|_|CoreError::internal("invalid captured explanation policy"))?;
                    let actual=match evidence {
                        ExplanationEvidence::Usage(usage)=>policy.cost(usage.input_tokens,usage.output_tokens)?,
                        ExplanationEvidence::NotCharged{reference_sha256}=>{
                            if reference_sha256.len()!=64 || !reference_sha256.bytes().all(|v|v.is_ascii_hexdigit()){return Err(CoreError::invalid("invalid reconciliation evidence digest"));} 0
                        }
                    };
                    if actual>policy.cost(128_000,1024)? || matches!(evidence,ExplanationEvidence::Usage(u) if u.input_tokens>128_000 || u.output_tokens>1024) {
                        sqlx::query("UPDATE explanation_profiles SET suspended=1 WHERE id=$1").bind(row.get::<String,_>("profile_id")).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    Self::explanation_release(tx,tenant,id,actual).await?;
                    sqlx::query("UPDATE explanation_operations SET evidence=$3,state=CASE WHEN state='suppressed' THEN state ELSE 'settled' END WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(encoded).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state='succeeded' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
                pub(crate) async fn explanation_erase(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,user:Option<&str>)->CoreResult<()> {
                    let rows=sqlx::query("SELECT id,attempted FROM explanation_operations WHERE tenant_id=$1 AND ($2='' OR user_id=$2)").bind(tenant).bind(user.unwrap_or("")).fetch_all(&mut **tx).await.map_err(db_error)?;
                    for row in rows {
                        let id:String=row.get("id");
                        Self::explanation_suppress_tx(tx, tenant, &id, row.get("attempted")).await?;
                    }
                    Ok(())
                }
                pub(crate) async fn explanation_erase_card(
                    tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, card: &str,
                ) -> CoreResult<()> {
                    let rows = sqlx::query("SELECT id,attempted FROM explanation_operations WHERE tenant_id=$1 AND card_id=$2")
                        .bind(tenant).bind(card).fetch_all(&mut **tx).await.map_err(db_error)?;
                    for row in rows {
                        Self::explanation_suppress_tx(tx, tenant, &row.get::<String,_>("id"), row.get("attempted")).await?;
                    }
                    Ok(())
                }
                async fn explanation_suppress_tx(
                    tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, id: &str, attempted: i64,
                ) -> CoreResult<()> {
                    if attempted == 0 { Self::explanation_release(tx, tenant, id, 0).await?; }
                    sqlx::query("UPDATE explanation_operations SET state='suppressed',result=NULL,result_bytes=0,cache_key=NULL,authority='{}',privacy=NULL WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state='dead',payload=$3 WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).bind(Json(serde_json::json!({}))).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
                pub(crate) async fn maintain_explanations_tx(tx:&mut sqlx::Transaction<'_, $db>,after:Option<(&str,&str)>)->CoreResult<Vec<(String,String)>> {
                    let (tenant,id)=after.unwrap_or(("",""));
                    let rows=sqlx::query(&format!("SELECT * FROM ({}) candidates WHERE tenant_id>$1 OR (tenant_id=$1 AND id>$2) ORDER BY tenant_id,id LIMIT 100",crate::recovery::EXPLANATIONS.sql)).bind(tenant).bind(id).fetch_all(&mut **tx).await.map_err(db_error)?;
                    let now=Self::asset_now(tx).await?;let mut page=Vec::new();
                    for row in rows {
                        let tenant:String=row.get("tenant_id");let id:String=row.get("id");
                        if row.get::<String,_>("state")=="pending" && row.get::<i64,_>("attempted")==0 {
                            Self::explanation_release(tx,&tenant,&id,0).await?;
                            sqlx::query("UPDATE explanation_operations SET state='cancelled',authority='{}',privacy=NULL,cache_key=NULL WHERE tenant_id=$1 AND id=$2").bind(&tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                            sqlx::query("UPDATE background_jobs SET state='dead',payload=$3 WHERE tenant_id=$1 AND id=$2").bind(&tenant).bind(&id).bind(Json(serde_json::json!({}))).execute(&mut **tx).await.map_err(db_error)?;
                        }
                        let stale:i64=sqlx::query_scalar(&format!("SELECT COUNT(*) FROM ({}) candidates WHERE tenant_id=$1 AND id=$2",crate::recovery::EXPLANATION_RESULTS.at("$3"))).bind(&tenant).bind(&id).bind(now).fetch_one(&mut **tx).await.map_err(db_error)?;
                        if stale!=0 {
                            sqlx::query("UPDATE explanation_operations SET result=NULL,result_bytes=0,authority='{}',privacy=NULL,cache_key=NULL,state=CASE WHEN state='settled' THEN 'expired' ELSE state END WHERE tenant_id=$1 AND id=$2").bind(&tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        }
                        page.push((tenant,id));
                    }
                    Ok(page)
                }
            }
            #[async_trait::async_trait]
            impl ExplanationRepo for $repo {
                async fn lookup_explanation(&self,p:&Principal,key:&str,command:Option<&str>)->CoreResult<Option<ExplanationRecord>> {
                    let mut tx=self.asset_tx().await?;
                    let result=Self::explanation_lookup_tx(&mut tx,p,key,command).await?;
                    tx.commit().await.map_err(db_error)?;Ok(result)
                }
                async fn admit_explanation(&self,p:&Principal,a:&ExplanationAdmission)->CoreResult<ExplanationRecord> {
                    validate_id(&a.request_id)?;
                    if a.command_hash.len()!=64 || !a.command_hash.bytes().all(|c|c.is_ascii_hexdigit()) || a.profile_id.len()!=64 || !a.profile_id.bytes().all(|c|c.is_ascii_hexdigit()) {return Err(CoreError::invalid("invalid explanation digest"));}
                    let mut tx=self.asset_tx().await?;
                    if let Some(old)=Self::explanation_lookup_tx(&mut tx,p,&a.request_id,Some(&a.command_hash)).await? {tx.commit().await.map_err(db_error)?;return Ok(old)}
                    a.context.validate()?;
                    if !Self::explanation_card_visible(&mut tx,p,&a.card_id).await? {return Err(CoreError::NotFound("card".into()));}
                    let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM cards WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&a.card_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if revision!=Some(i64::from(a.revision)){return Err(CoreError::Conflict("explanation card changed".into()));}
                    let plan:String=sqlx::query_scalar("SELECT plan FROM tenants WHERE id=$1").bind(&p.tenant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let now=Self::asset_now(&mut tx).await?;
                    let policy=a.policy.as_ref().filter(|_|matches!(plan.as_str(), "self_hosted" | "free" | "pro" | "team"));
                    if let Some(policy)=policy {policy.validate(now)?;}
                    // 缺少用途证据时，在任何预算、任务或 attempt 写入前退出。
                    let privacy = if policy.is_some() {
                        Some(Self::explanation_privacy_tx(&mut tx, &p.tenant_id, &p.user_id, None).await?)
                    } else { None };
                    let financial_id=policy.map(Self::explanation_financial_id).unwrap_or_else(||a.profile_id.clone());
                    let key=if policy.is_some(){a.cache_key.as_deref()}else{None};
                    if let Some(key)=key {
                        let row=sqlx::query("SELECT * FROM explanation_operations WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3 AND revision=$4 AND cache_key=$5 AND account_generation=$6 AND membership_generation=$7 AND privacy=$9 AND (state IN ('pending','unresolved') OR (state='settled' AND result IS NOT NULL AND expires_at_ms>$8)) ORDER BY id LIMIT 1")
                            .bind(&p.tenant_id).bind(&p.user_id).bind(&a.card_id).bind(i64::from(a.revision)).bind(key).bind(p.auth_generation).bind(p.membership_generation).bind(now).bind(&privacy).fetch_optional(&mut *tx).await.map_err(db_error)?;
                        if let Some(row)=row {
                            sqlx::query("INSERT INTO explanation_requests(tenant_id,user_id,request_id,command_hash,operation_id) VALUES($1,$2,$3,$4,$5)").bind(&p.tenant_id).bind(&p.user_id).bind(&a.request_id).bind(&a.command_hash).bind(row.get::<String,_>("id")).execute(&mut *tx).await.map_err(db_error)?;
                            let result=Self::explanation_record(&row,&a.request_id,now,true)?;tx.commit().await.map_err(db_error)?;return Ok(result)
                        }
                    }
                    let id=memoswish_core::ids::new_id();
                    let period=chrono::DateTime::from_timestamp_millis(now).ok_or_else(||CoreError::internal("invalid database time"))?.format("%Y-%m").to_string();
                    let mut holds=Vec::new();
                    if let Some(policy)=policy {
                        let encoded=serde_json::to_string(policy).map_err(|_|CoreError::internal("invalid explanation policy"))?;
                        sqlx::query("INSERT INTO explanation_profiles(id,policy) VALUES($1,$2) ON CONFLICT(id) DO NOTHING").bind(&financial_id).bind(&encoded).execute(&mut *tx).await.map_err(db_error)?;
                        let row=sqlx::query("SELECT policy,suspended FROM explanation_profiles WHERE id=$1").bind(&financial_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                        if row.get::<String,_>("policy")!=encoded || row.get::<i64,_>("suspended")!=0 {return Err(CoreError::Forbidden("explanation profile changed or suspended".into()));}
                        let limits=serde_json::to_string(&(policy.cache_entry_bytes,policy.cache_tenant_bytes,policy.cache_deployment_bytes,policy.cache_ttl_ms)).map_err(|_|CoreError::internal("invalid explanation cache limits"))?;
                        sqlx::query("INSERT INTO explanation_cache_limits(deployment_id,limits) VALUES($1,$2) ON CONFLICT(deployment_id) DO NOTHING").bind(&policy.deployment_id).bind(&limits).execute(&mut *tx).await.map_err(db_error)?;
                        let captured:String=sqlx::query_scalar("SELECT limits FROM explanation_cache_limits WHERE deployment_id=$1").bind(&policy.deployment_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                        if captured!=limits {return Err(CoreError::Conflict("explanation cache limits differ across replicas".into()));}
                        let amount=policy.cost(128_000,1024)?;
                        for (scope,cap) in [(format!("tenant:{}:{}",policy.deployment_id,p.tenant_id),policy.tenant_limit),(format!("deployment:{}",policy.deployment_id),policy.deployment_limit),(format!("provider:{}",policy.provider_account),policy.provider_limit)] {
                            sqlx::query("INSERT INTO explanation_accounts(scope,period,currency,cap,exposure_cap) VALUES($1,$2,$3,$4,$5) ON CONFLICT(scope,period) DO NOTHING").bind(&scope).bind(&period).bind(&policy.currency).bind(cap).bind(policy.unresolved_limit).execute(&mut *tx).await.map_err(db_error)?;
                            let row=sqlx::query("SELECT * FROM explanation_accounts WHERE scope=$1 AND period=$2").bind(&scope).bind(&period).fetch_one(&mut *tx).await.map_err(db_error)?;
                            let incompatible:i64=sqlx::query_scalar("SELECT COUNT(*) FROM explanation_accounts WHERE scope=$1 AND (currency<>$2 OR exposure_cap<>$3)").bind(&scope).bind(&policy.currency).bind(policy.unresolved_limit).fetch_one(&mut *tx).await.map_err(db_error)?;
                            if row.get::<i64,_>("cap")!=cap || incompatible!=0 {return Err(CoreError::Conflict("explanation account configuration differs across replicas".into()));}
                            let used:i64=row.get("committed");let held:i64=row.get("held");
                            let exposure:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(held),0) AS BIGINT) FROM explanation_accounts WHERE scope=$1").bind(&scope).fetch_one(&mut *tx).await.map_err(db_error)?;
                            if used>cap || held>cap-used || amount>cap-used-held || exposure>policy.unresolved_limit || amount>policy.unresolved_limit-exposure {return Err(CoreError::QuotaExceeded("explanation budget exhausted".into()));}
                            holds.push((scope,amount));
                        }
                    }
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,state,max_attempts,available_at_ms) VALUES($1,$2,'explanation',$2,$3,$4,$5,$6,1,$7)")
                        .bind(&p.tenant_id).bind(&id).bind(Json(serde_json::to_value(&a.context).map_err(|_|CoreError::internal("invalid explanation context"))?)).bind(&p.user_id).bind(p.membership_generation).bind(if policy.is_some(){"queued"}else{"succeeded"}).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    let encoded=policy.map(serde_json::to_string).transpose().map_err(|_|CoreError::internal("invalid explanation policy"))?;
                    sqlx::query("INSERT INTO explanation_operations(tenant_id,id,user_id,card_id,revision,account_generation,membership_generation,profile_id,policy,cache_key,period,state,configuration_id,authority) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                        .bind(&p.tenant_id).bind(&id).bind(&p.user_id).bind(&a.card_id).bind(i64::from(a.revision)).bind(p.auth_generation).bind(p.membership_generation).bind(&financial_id).bind(encoded).bind(key).bind(&period).bind(if policy.is_some(){"pending"}else{"local"}).bind(&a.profile_id).bind(serde_json::to_string(&Self::explanation_authority(p)).map_err(|_|CoreError::internal("invalid explanation authority"))?).execute(&mut *tx).await.map_err(db_error)?;
                    for (scope,amount) in holds {
                        sqlx::query("INSERT INTO explanation_holds(tenant_id,operation_id,scope,period,amount) VALUES($1,$2,$3,$4,$5)").bind(&p.tenant_id).bind(&id).bind(&scope).bind(&period).bind(amount).execute(&mut *tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE explanation_accounts SET held=held+$3 WHERE scope=$1 AND period=$2").bind(scope).bind(&period).bind(amount).execute(&mut *tx).await.map_err(db_error)?;
                    }
                    sqlx::query("UPDATE explanation_operations SET privacy=$3 WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(&id).bind(privacy).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO explanation_requests(tenant_id,user_id,request_id,command_hash,operation_id) VALUES($1,$2,$3,$4,$5)").bind(&p.tenant_id).bind(&p.user_id).bind(&a.request_id).bind(&a.command_hash).bind(&id).execute(&mut *tx).await.map_err(db_error)?;
                    let result=Self::explanation_lookup_tx(&mut tx,p,&a.request_id,None).await?.unwrap();
                    tx.commit().await.map_err(db_error)?;Ok(result)
                }
                async fn suppress_explanation(&self,p:&Principal,key:&str)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;
                    let record=Self::explanation_lookup_tx(&mut tx,p,key,None).await?.ok_or_else(||CoreError::NotFound("explanation request".into()))?;
                    let row=sqlx::query("SELECT attempted,policy FROM explanation_operations WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&record.id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if row.get::<Option<String>,_>("policy").is_some() {
                        if row.get::<i64,_>("attempted")==0 {Self::explanation_release(&mut tx,&p.tenant_id,&record.id,0).await?;}
                        sqlx::query("UPDATE explanation_operations SET state='suppressed',result=NULL,result_bytes=0,cache_key=NULL,authority='{}' WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&record.id).execute(&mut *tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE background_jobs SET state='dead' WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&record.id).execute(&mut *tx).await.map_err(db_error)?;
                    }
                    tx.commit().await.map_err(db_error)
                }
                async fn begin_explanation_attempt(&self,p:&Principal,key:&str)->CoreResult<bool> {
                    let mut tx=self.asset_tx().await?;
                    let Some(record)=Self::explanation_lookup_tx(&mut tx,p,key,None).await? else {return Ok(false)};
                    if record.operation.disposition!=ExplainDisposition::Pending {return Ok(false)}
                    let row=sqlx::query("SELECT o.id,o.policy,o.profile_id,o.authority,o.privacy FROM explanation_operations o JOIN explanation_requests r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.request_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(key).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let policy:ExplanationPolicy=serde_json::from_str(&row.get::<String,_>("policy")).map_err(|_|CoreError::internal("invalid captured explanation policy"))?;
                    let authority:ImportAuthority=serde_json::from_str(&row.get::<String,_>("authority")).map_err(|_|CoreError::Forbidden("original explanation authority unavailable".into()))?;
                    Self::content_authorize(&mut tx,&authority,Permission::ContentRead,false).await?;
                    let fence: String = row.get("privacy");
                    Self::explanation_privacy_tx(&mut tx, &p.tenant_id, &p.user_id, Some(&fence)).await?;
                    policy.validate(Self::asset_now(&mut tx).await?)?;
                    let plan:String=sqlx::query_scalar("SELECT plan FROM tenants WHERE id=$1").bind(&p.tenant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let suspended:i64=sqlx::query_scalar("SELECT suspended FROM explanation_profiles WHERE id=$1").bind(row.get::<String,_>("profile_id")).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if !matches!(plan.as_str(), "self_hosted" | "free" | "pro" | "team") || suspended!=0 {return Err(CoreError::Forbidden("external explanation eligibility is absent".into()));}
                    let id:String=row.get("id");
                    let changed=sqlx::query("UPDATE explanation_operations SET attempted=1,state='unresolved' WHERE tenant_id=$1 AND id=$2 AND state='pending' AND attempted=0").bind(&p.tenant_id).bind(&id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    sqlx::query("UPDATE background_jobs SET attempts=1,state='dead' WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(changed==1)
                }
                async fn settle_explanation(&self,tenant:&str,id:&str,evidence:&ExplanationEvidence)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;Self::explanation_settle_tx(&mut tx,tenant,id,evidence).await?;tx.commit().await.map_err(db_error)
                }
                async fn reconcile_explanation(&self,p:&Principal,key:&str,evidence:&ExplanationEvidence)->CoreResult<ExplainOperation> {
                    validate_id(key)?;
                    p.require(Permission::BillingManage)?;
                    let mut tx=self.asset_tx().await?;Self::explanation_authorize(&mut tx,p).await?;
                    Self::content_authorize(&mut tx,&Self::explanation_authority(p),Permission::BillingManage,false).await?;
                    // 调用身份查找和结算共用注册锁，只允许当前主体核账，不授予正文或重发权限。
                    let id:String=sqlx::query_scalar("SELECT operation_id FROM explanation_requests WHERE tenant_id=$1 AND user_id=$2 AND request_id=$3").bind(&p.tenant_id).bind(&p.user_id).bind(key).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("explanation request".into()))?;
                    Self::explanation_settle_tx(&mut tx,&p.tenant_id,&id,evidence).await?;
                    let row=sqlx::query("SELECT policy,evidence,attempted,period,state FROM explanation_operations WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let disposition=serde_json::from_value(serde_json::Value::String(row.get("state"))).map_err(|_|CoreError::internal("invalid explanation state"))?;
                    let receipt=Self::explanation_receipt(&row,key,disposition)?;
                    tx.commit().await.map_err(db_error)?;Ok(receipt)
                }
                async fn publish_explanation(&self,p:&Principal,key:&str,result:&CardExplanation)->CoreResult<bool> {
                    let mut tx=self.asset_tx().await?;
                    Self::explanation_authorize(&mut tx,p).await?;
                    let row=sqlx::query("SELECT o.* FROM explanation_operations o JOIN explanation_requests r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.request_id=$3").bind(&p.tenant_id).bind(&p.user_id).bind(key).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("explanation operation".into()))?;
                    if row.get::<String,_>("state")!="settled" || row.get::<String,_>("card_id")!=result.card_id || Some(row.get::<i64,_>("account_generation"))!=p.auth_generation || Some(row.get::<i64,_>("membership_generation"))!=p.membership_generation || !Self::explanation_card_current(&mut tx,&p.tenant_id,&row).await? {return Ok(false)}
                    if !Self::explanation_card_visible(&mut tx,p,&result.card_id).await? {return Ok(false)}
                    let plan:String=sqlx::query_scalar("SELECT plan FROM tenants WHERE id=$1").bind(&p.tenant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if !matches!(plan.as_str(), "self_hosted" | "free" | "pro" | "team") {return Ok(false)}
                    let fence: String = row.get("privacy");
                    Self::explanation_privacy_tx(&mut tx, &p.tenant_id, &p.user_id, Some(&fence)).await?;
                    let authority:ImportAuthority=serde_json::from_str(&row.get::<String,_>("authority")).map_err(|_|CoreError::Forbidden("original explanation authority unavailable".into()))?;
                    Self::content_authorize(&mut tx,&authority,Permission::ContentRead,false).await?;
                    if row.get::<Option<String>,_>("result").is_some(){return Ok(true)}
                    let policy:ExplanationPolicy=serde_json::from_str(&row.get::<String,_>("policy")).map_err(|_|CoreError::internal("invalid captured explanation policy"))?;
                    let mut clean=result.clone();clean.operation=None;
                    let encoded=serde_json::to_string(&clean).map_err(|_|CoreError::internal("invalid explanation result"))?;
                    let size=i64::try_from(encoded.len()).map_err(|_|CoreError::invalid("explanation result too large"))?;
                    if size>policy.cache_entry_bytes{return Ok(false)}
                    let now=Self::asset_now(&mut tx).await?;
                    // 有界清理过期正文，容量按物理保存的全部字节计算。
                    sqlx::query("UPDATE explanation_operations SET result=NULL,result_bytes=0,state=CASE WHEN state='settled' THEN 'expired' ELSE state END WHERE (tenant_id,id) IN (SELECT tenant_id,id FROM explanation_operations WHERE result IS NOT NULL AND expires_at_ms<=$1 ORDER BY tenant_id,id LIMIT 100)").bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    let tenant_bytes:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(result_bytes),0) AS BIGINT) FROM explanation_operations WHERE tenant_id=$1").bind(&p.tenant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let deployment_bytes:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(result_bytes),0) AS BIGINT) FROM explanation_operations").fetch_one(&mut *tx).await.map_err(db_error)?;
                    if tenant_bytes>policy.cache_tenant_bytes-size || deployment_bytes>policy.cache_deployment_bytes-size{return Ok(false)}
                    let expiry=now.checked_add(policy.cache_ttl_ms).ok_or_else(||CoreError::invalid("explanation expiry overflows"))?;
                    sqlx::query("UPDATE explanation_operations SET result=$3,result_bytes=$4,expires_at_ms=$5 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(row.get::<String,_>("id")).bind(encoded).bind(size).bind(expiry).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(true)
                }
                async fn maintain_explanations(&self,after:Option<(&str,&str)>)->CoreResult<Vec<(String,String)>> {
                    let mut tx=self.asset_tx().await?;
                    let page=Self::maintain_explanations_tx(&mut tx,after).await?;
                    tx.commit().await.map_err(db_error)?;Ok(page)
                }
            }
        };
    };
}
pub(crate) use explanations_impl;
