//! 两个传输共用持久导入；进程内拥有者负责等待，SQL 负责重启恢复。
use crate::Services;
use memoswish_content::{
    apkg::{ApkgOptions, ApkgReport},
    imports::{fingerprint, import_result},
};
use memoswish_core::{CoreError, CoreResult, Principal, imports::*};
use memoswish_protocol::{Deck, DeckPack};

impl Services {
    /// 当前凭据只读取原始身份的导入处置，不接受内部任务 ID。
    pub async fn import_status(
        &self,
        p: &Principal,
        key: &str,
        credential: Option<ImportCredential>,
    ) -> CoreResult<serde_json::Value> {
        self.auth.require_privacy_collection(p).await?;
        let authority = ImportAuthority::capture(p, credential);
        let operation = self
            .content
            .import_repository()
            .import_status(&authority, key)
            .await?
            .ok_or_else(|| CoreError::NotFound("import request".into()))?;
        Ok(serde_json::json!({"request_id": key, "outcome": operation.outcome}))
    }

    pub async fn import_apkg_with_identity(
        &self,
        p: &Principal,
        bytes: Vec<u8>,
        options: ApkgOptions,
        key: Option<String>,
        token_hash: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<ApkgReport> {
        self.auth.require_privacy_collection(p).await?;
        let services = self.clone();
        let p = p.clone();
        self.operations
            .spawn(async move {
                let authority = ImportAuthority::capture(&p, token_hash);
                let fingerprint = fingerprint("apkg", &(memoswish_core::ids::sha256_hex(&bytes), &options), false)?;
                let key = key.unwrap_or_else(memoswish_core::ids::new_id);
                validate_request_id(&key)?;
                let repo = services.content.import_repository();
                let mut preparation = None;
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                let operation = match repo.lookup_import(&authority, &key, &fingerprint).await? {
                    Some(existing) => existing,
                    None => {
                        preparation = Some(services.content.prepare_apkg(&p, bytes, options).await?);
                        let work = preparation.as_ref().unwrap().work()?;
                        let limit = services.quota.card_write_limit(&p.tenant_id).await?;
                        control.begin_acceptance()?;
                        repo.accept_import(
                            &authority,
                            &key,
                            &fingerprint,
                            &work,
                            limit,
                            services.content.import_staging_limit(),
                        )
                        .await?
                    }
                };
                control.accepted();
                let result = import_result(services.content.drive_import(&p.tenant_id, &operation.id).await?)?;
                drop(preparation);
                serde_json::from_value(result).map_err(CoreError::internal)
            })?
            .await
            .map_err(|_| CoreError::Unavailable("import owner interrupted; retry the original identity".into()))?
    }
    pub async fn import_deck_pack_with_identity(
        &self,
        p: &Principal,
        pack: DeckPack,
        auto_tts: bool,
        key: Option<String>,
        token_hash: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<Deck> {
        self.import_deck_pack_input(p, input_value(&pack)?, auto_tts, key, token_hash).await
    }
    /// 传输入口保留原始 JSON，不能先解码成当前线模型。
    pub async fn import_deck_pack_input(
        &self,
        p: &Principal,
        pack: serde_json::Value,
        auto_tts: bool,
        key: Option<String>,
        token_hash: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<Deck> {
        self.auth.require_privacy_collection(p).await?;
        let identity_pack: DeckPack = decode_input(pack.clone(), IMPORT_CONTENT_BYTES)?;
        let privacy = if auto_tts { self.media.default_tts_privacy(p).await? } else { None };
        let services = self.clone();
        let p = p.clone();
        self.operations
            .spawn(async move {
                let mut authority = ImportAuthority::capture(&p, token_hash);
                authority.privacy = privacy;
                let fingerprint = fingerprint("deckpack", &identity_pack, auto_tts)?;
                let key = key.unwrap_or_else(memoswish_core::ids::new_id);
                validate_request_id(&key)?;
                let repo = services.content.import_repository();
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                let operation = match repo.lookup_import(&authority, &key, &fingerprint).await? {
                    Some(existing) => existing,
                    None => {
                        let work = services.content.prepare_deck_pack(&p, pack, auto_tts)?;
                        let limit = services.quota.card_write_limit(&p.tenant_id).await?;
                        control.begin_acceptance()?;
                        repo.accept_import(
                            &authority,
                            &key,
                            &fingerprint,
                            &work,
                            limit,
                            services.content.import_staging_limit(),
                        )
                        .await?
                    }
                };
                control.accepted();
                let result = import_result(services.content.drive_import(&p.tenant_id, &operation.id).await?)?;
                // 语音准入失败不改变已提交内容；未完成交接由同一维护分页继续。
                if services.media.executes_work() {
                    let _ = services.advance_import_followups(&p.tenant_id, &operation.id).await;
                }
                serde_json::from_value(result).map_err(CoreError::internal)
            })?
            .await
            .map_err(|_| CoreError::Unavailable("import owner interrupted; retry the original identity".into()))?
    }
    pub fn recover_imports(&self) -> CoreResult<tokio::task::JoinHandle<CoreResult<()>>> {
        self.recover_scheduled(memoswish_core::maintenance::TaskKind::ImportRecovery)
    }
    pub(crate) async fn advance_import_followups(&self, tenant: &str, id: &str) -> CoreResult<()> {
        let repo = self.content.import_repository();
        for followup in repo.import_followups(tenant, id).await? {
            let mut p = followup.authority.principal();
            // S17 持久请求者使用相同的原始摘要和期限，不能补给后继凭据。
            p.session_access_hash = match p.via.as_str() {
                "api_token" => followup.authority.token_hash.as_ref().map(|h| format!("api:{h}")),
                "mcp_oauth" => followup.authority.token_hash.as_ref().map(|h| format!("oauth:{h}")),
                "jwt" => followup.authority.expires_at.map(|e| format!("jwt:{e}")),
                _ => p.session_access_hash,
            };
            let request_id = format!("import:{id}:{}", followup.card_id);
            let mut options = memoswish_media::SynthesizeOptions::default();
            options.expected_revisions.insert(followup.card_id.clone(), followup.revision);
            let outcome = match self
                .media
                .submit_import_tts(
                    &p,
                    &request_id,
                    std::slice::from_ref(&followup.card_id),
                    &options,
                    followup.authority.privacy.as_ref(),
                )
                .await
            {
                Ok(submission) if submission.complete => {
                    if submission.items.iter().all(|i| {
                        i.receipt
                            .as_ref()
                            .is_some_and(|r| r.disposition == memoswish_protocol::TtsDisposition::Attached)
                    }) {
                        "succeeded"
                    } else {
                        "failed"
                    }
                }
                Ok(submission) => {
                    for item in submission.items {
                        let media = self.media.clone();
                        let tenant = tenant.to_string();
                        // 持久提交已交接；后台执行仍由共享 tracker 持有，不等待 provider。
                        drop(
                            self.operations
                                .spawn(async move { media.recover_submission_item(&tenant, &item.item_id).await })?,
                        );
                    }
                    "running"
                }
                Err(
                    CoreError::Forbidden(_)
                    | CoreError::Unauthorized(_)
                    | CoreError::Conflict(_)
                    | CoreError::NotFound(_)
                    | CoreError::Invalid(_)
                    | CoreError::QuotaExceeded(_),
                ) => "failed",
                // SQL 与存储故障不伪装终态，重启仍能发现原交接身份。
                Err(_) => "retry",
            };
            repo.import_followup(tenant, id, &followup.card_id, outcome).await?;
        }
        Ok(())
    }
}
