//! REST/MCP 严格编辑共享命令；不暗中合成媒体或重试冲突。
use crate::{Services, asset_delivery::render_card};
use memoswish_core::{CoreResult, Principal};
use memoswish_protocol::*;
impl Services {
    pub async fn save_card(&self, p: &Principal, save: CardSave) -> CoreResult<Card> {
        p.require(memoswish_core::Permission::ContentWrite)?;
        memoswish_core::content_lifecycle::validate_save(&save)?;
        let content = self.content.clone();
        let owner = p.clone();
        self.own_authoring(p, 1, async move { content.save_card(&owner, save).await })
            .await
            .map(|c| render_card(c, "content"))
    }
    pub async fn publish_card(&self, p: &Principal, id: &str, command: PublicationCommand) -> CoreResult<Card> {
        p.require(memoswish_core::Permission::ContentWrite)?;
        let content = self.content.clone();
        let owner = p.clone();
        let id = id.to_owned();
        self.own_authoring(p, 1, async move { content.publish_card(&owner, &id, command).await })
            .await
            .map(|c| render_card(c, "content"))
    }
    pub async fn edit_deck(&self, p: &Principal, id: &str, edit: &DeckEdit) -> CoreResult<Deck> {
        self.content.edit_deck(p, id, edit).await
    }
    pub async fn content_revisions(
        &self,
        p: &Principal,
        id: &str,
        before: u64,
        limit: u32,
    ) -> CoreResult<Vec<CardRevision>> {
        let mut revisions = self.content.revisions(p, id, before, limit).await?;
        for revision in &mut revisions {
            for (_, asset) in memoswish_core::assets::card_asset_slots_mut(&mut revision.card) {
                asset.url.clear();
            }
        }
        Ok(revisions)
    }
    pub async fn report_content(&self, p: &Principal, id: &str, report: &ReportCreate) -> CoreResult<ContentReport> {
        self.limiter.check(&p.tenant_id, 1.0).await?;
        let content = self.content.clone();
        let owner = p.clone();
        let id = id.to_owned();
        let report = report.clone();
        self.own_authoring(p, 0, async move { content.report(&owner, &id, &report).await }).await
    }
    pub async fn content_reports(
        &self,
        p: &Principal,
        id: &str,
        offset: u32,
        limit: u32,
    ) -> CoreResult<Vec<ContentReport>> {
        self.content.reports(p, id, offset, limit).await
    }
}

impl Services {
    pub async fn starter_catalog(&self, p: &Principal) -> CoreResult<Vec<StarterDeck>> {
        p.require(memoswish_core::Permission::ContentRead)?;
        Ok(memoswish_content::starter::catalog())
    }
    pub async fn install_starter(
        &self,
        p: &Principal,
        id: &str,
        key: &str,
        credential: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<Deck> {
        memoswish_core::imports::validate_request_id(key)?;
        self.import_deck_pack_with_identity(
            p,
            memoswish_content::starter::pack(id)?,
            false,
            Some(format!("starter:{}", memoswish_core::ids::sha256_hex(key.as_bytes()))),
            credential,
        )
        .await
    }
}

impl Services {
    pub async fn create_authored_deck(&self, p: &Principal, input: memoswish_content::NewDeck) -> CoreResult<Deck> {
        self.content.create_authored_deck(p, input).await
    }

    pub async fn import_authored_content(
        &self,
        p: &Principal,
        input: ContentImport,
        credential: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<Deck> {
        self.import_authored_content_input(p, memoswish_core::imports::input_value(&input)?, credential).await
    }
    /// 严格导入同样沿用原始 JSON 预算及 S18 持久工作。
    pub async fn import_authored_content_input(
        &self,
        p: &Principal,
        mut wire: serde_json::Value,
        credential: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<Deck> {
        use memoswish_core::imports::*;
        self.auth.require_privacy_collection(p).await?;
        let input: ContentImport = decode_input(wire.clone(), memoswish_content::deckpack::DOCUMENT_BYTES + 1024)?;
        validate_request_id(&input.idempotency_key)?;
        memoswish_content::deckpack::validate_input(&wire["pack"])?;
        let services = self.clone();
        let p = p.clone();
        self.operations
            .spawn(async move {
                let authority = ImportAuthority::capture(&p, credential);
                let fingerprint = memoswish_content::imports::fingerprint("authored-import", &input, false)?;
                let key = format!("author:{}", memoswish_core::ids::sha256_hex(input.idempotency_key.as_bytes()));
                let repo = services.content.import_repository();
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                let operation = match repo.lookup_import(&authority, &key, &fingerprint).await? {
                    Some(existing) => existing,
                    None => {
                        let mut work = services.content.prepare_portable_deck_pack(&p, wire["pack"].take())?;
                        for card in &mut work.cards {
                            if let Some(metadata) = &mut card.content {
                                metadata.publication = if input.publish { "published" } else { "draft" }.into();
                            }
                        }
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
                let result = memoswish_content::imports::import_result(
                    services.content.drive_import(&p.tenant_id, &operation.id).await?,
                )?;
                serde_json::from_value(result).map_err(memoswish_core::CoreError::internal)
            })?
            .await
            .map_err(|_| {
                memoswish_core::CoreError::Unavailable("import owner interrupted; retry original identity".into())
            })?
    }
}

impl Services {
    pub async fn save_generated_cards(
        &self,
        p: &Principal,
        drafts: Vec<CardDraft>,
        publish: bool,
        method: &str,
    ) -> CoreResult<Vec<Card>> {
        p.require(memoswish_core::Permission::ContentWrite)?;
        if drafts.is_empty() || drafts.len() > 200 {
            return Err(memoswish_core::CoreError::invalid("provide 1..=200 cards"));
        }
        for draft in &drafts {
            memoswish_core::content_lifecycle::validate_save(&CardSave {
                card: draft.clone(),
                publish,
                provenance: None,
                report_id: None,
            })?;
        }
        let content = self.content.clone();
        let owner = p.clone();
        let method = method.to_owned();
        self.own_authoring(p, drafts.len() as u64, async move {
            content.save_generated_cards(&owner, drafts, publish, &method).await
        })
        .await
        .map(|cards| crate::asset_delivery::render_cards(cards, "content"))
    }
}

impl Services {
    pub async fn import_authored_apkg(
        &self,
        p: &Principal,
        bytes: Vec<u8>,
        input: ContentApkgImport,
        credential: Option<memoswish_core::imports::ImportCredential>,
    ) -> CoreResult<memoswish_content::apkg::ApkgReport> {
        use memoswish_core::imports::*;
        self.auth.require_privacy_collection(p).await?;
        let key = input
            .apkg
            .request_id
            .as_ref()
            .ok_or_else(|| memoswish_core::CoreError::invalid("strict APKG import requires request_id"))?;
        validate_request_id(key)?;
        let key = format!("author-apkg:{}", memoswish_core::ids::sha256_hex(key.as_bytes()));
        let options = memoswish_content::apkg::ApkgOptions { title: input.apkg.title, language: input.apkg.language };
        let services = self.clone();
        let p = p.clone();
        self.operations
            .spawn(async move {
                let authority = ImportAuthority::capture(&p, credential);
                let fingerprint = memoswish_content::imports::fingerprint(
                    "authored-apkg",
                    &(memoswish_core::ids::sha256_hex(&bytes), &options, input.publish),
                    false,
                )?;
                let repo = services.content.import_repository();
                let mut preparation = None;
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                let operation = match repo.lookup_import(&authority, &key, &fingerprint).await? {
                    Some(existing) => existing,
                    None => {
                        preparation = Some(services.content.prepare_apkg(&p, bytes, options).await?);
                        let mut work = preparation.as_ref().unwrap().work()?;
                        for card in &mut work.cards {
                            if let Some(metadata) = &mut card.content {
                                metadata.publication = if input.publish { "published" } else { "draft" }.into();
                            }
                        }
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
                let result = memoswish_content::imports::import_result(
                    services.content.drive_import(&p.tenant_id, &operation.id).await?,
                )?;
                drop(preparation);
                serde_json::from_value(result).map_err(memoswish_core::CoreError::internal)
            })?
            .await
            .map_err(|_| {
                memoswish_core::CoreError::Unavailable("APKG import owner interrupted; retry original identity".into())
            })?
    }
}

impl Services {
    // 严格作者命令从开始计量起归应用拥有；取消与断连不能丢弃提交 future。
    async fn own_authoring<T, F>(&self, p: &Principal, writes: u64, mutation: F) -> CoreResult<T>
    where
        T: Send + 'static,
        F: Future<Output = CoreResult<T>> + Send + 'static,
    {
        self.auth.require_privacy_collection(p).await?;
        let quota = self.quota.clone();
        let owner = p.clone();
        self.operations
            .spawn(async move {
                let control = crate::OperationControl::current();
                control.begin_acceptance()?;
                if writes > 0 {
                    quota.consume(&owner, memoswish_auth::Metric::CardWrites, writes).await?;
                }
                let result = mutation.await?;
                control.accepted();
                Ok(result)
            })?
            .await
            .map_err(|_| {
                memoswish_core::CoreError::Unavailable(
                    "authoring owner interrupted; query current content before retrying".into(),
                )
            })?
    }
}
