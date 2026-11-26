//! 在短 SQL 事务内物化白名单投影；对象读取由应用层完成后再次复核授权。

macro_rules! account_export_impl {
    ($repo:ty, $db:ty) => {
        impl $repo {
            async fn export_rows(
                tx: &mut sqlx::Transaction<'_, $db>,
                table: &str,
                columns: &[&str],
                filter: &str,
                tenant: &str,
                user: &str,
            ) -> memoswish_core::CoreResult<Vec<serde_json::Value>> {
                use sqlx::Row;
                let now=if table=="explanation_operations" {Self::asset_now(tx).await?}else{0};
                let mut projection = columns.iter().map(|c| {
                    if table=="explanation_operations" && *c=="context" {
                        "(SELECT CAST(payload AS TEXT) FROM background_jobs j WHERE j.tenant_id=explanation_operations.tenant_id AND j.id=explanation_operations.id) AS context".to_string()
                    } else if table=="explanation_operations" && *c=="result" {
                        format!("CASE WHEN expires_at_ms>{now} AND state='settled' AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=explanation_operations.tenant_id AND t.plan IN ('self_hosted','free','pro','team')) AND EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=explanation_operations.tenant_id AND c.id=explanation_operations.card_id AND c.revision=explanation_operations.revision AND (c.publication='published' OR EXISTS(SELECT 1 FROM tenant_memberships m WHERE m.tenant_id=c.tenant_id AND m.user_id=$2 AND m.role IN ('owner','admin','editor')))) THEN result ELSE NULL END AS result")
                    }else{format!("CAST({c} AS TEXT) AS {c}")}
                }).collect::<Vec<_>>().join(",");
                if table == "explanation_operations" {
                    projection.push_str(",privacy AS explanation_privacy");
                }
                let rows = sqlx::query(&format!("SELECT {projection} FROM {table} WHERE {filter}"))
                    .bind(tenant)
                    .bind(user)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(db_err)?;
                let mut values = Vec::new();
                for row in rows {
                    let mut value = serde_json::Map::new();
                    for col in columns {
                        let mut raw: Option<String> = row.try_get(*col).map_err(db_err)?;
                        if table == "explanation_operations" && *col == "result" && raw.is_some() {
                            let fence: Option<String> = row.try_get("explanation_privacy").map_err(db_err)?;
                            match fence {
                                Some(fence) => match Self::explanation_privacy_tx(tx, tenant, user, Some(&fence)).await {
                                    Ok(_) => {},
                                    Err(memoswish_core::CoreError::Forbidden(_)) => raw = None,
                                    Err(error) => return Err(error),
                                },
                                None => raw = None,
                            }
                        }
                        let mut parsed = match raw {
                            None => serde_json::Value::Null,
                            Some(raw) if *col == "metadata" => {
                                let metadata: serde_json::Value = serde_json::from_str(&raw)
                                    .map_err(|_| memoswish_core::CoreError::internal("invalid grant export metadata"))?;
                                let safe = ["resource", "scopes", "created_at"]
                                    .into_iter()
                                    .filter_map(|key| metadata.get(key).map(|v| (key.to_string(), v.clone())))
                                    .collect::<serde_json::Map<_, _>>();
                                serde_json::Value::Object(safe)
                            }
                            Some(raw) if table == "favorite_operations" && *col == "receipt" => {
                                let receipt: memoswish_protocol::FavoriteState=serde_json::from_str(&raw).map_err(|_|memoswish_core::CoreError::internal("invalid favorite export receipt"))?;
                                serde_json::to_value(receipt).map_err(memoswish_core::CoreError::internal)?
                            }
                            Some(raw) if *col == "receipt" => {
                                let receipt: memoswish_protocol::TtsAttachmentReceipt = serde_json::from_str(&raw)
                                    .map_err(|_| {
                                        memoswish_core::CoreError::internal("invalid attachment export receipt")
                                    })?;
                                serde_json::to_value(receipt).map_err(memoswish_core::CoreError::internal)?
                            }
                            Some(raw)
                                if [
                                    "body",
                                    "tags",
                                    "scopes",
                                    "recent_card_ids",
                                    "application_provenance",
                                    "result",
                                    "context",
                                ]
                                .contains(col) =>
                            {
                                serde_json::from_str(&raw)
                                    .map_err(|_| memoswish_core::CoreError::internal("invalid stored export JSON"))?
                            }
                            Some(raw)
                                if [
                                    "rating",
                                    "reps",
                                    "lapses",
                                    "exposures",
                                    "starred",
                                    "last_rating",
                                    "stability",
                                    "difficulty",
                                    "expires_at",
                                    "revoked",
                                    "auth_time",
                                    "amount",
                                    "next_slot",
                                    "slot",
                                ]
                                .contains(col) =>
                            {
                                serde_json::from_str(&raw).unwrap_or(serde_json::Value::String(raw))
                            }
                            Some(raw) => serde_json::Value::String(raw),
                        };
                        if table=="content_revisions" && *col=="body" {memoswish_core::assets::clear_historical_delivery_urls(&mut parsed);}
                        value.insert(col.to_string(), parsed);
                    }
                    values.push(if columns == ["body"] {
                        value.remove("body").unwrap()
                    } else {
                        serde_json::Value::Object(value)
                    });
                }
                Ok(values)
            }

            pub(crate) async fn export_workspace_authorize(
                tx: &mut sqlx::Transaction<'_, $db>,
                p: &memoswish_core::Principal,
                full: bool,
            ) -> memoswish_core::CoreResult<()> {
                if p.via == "jwt" {
                    let iat = p.legacy_issued_at.ok_or_else(|| {
                        memoswish_core::CoreError::Unauthorized("legacy credential evidence is missing".into())
                    })?;
                    Self::legacy_session_tx(tx, &p.user_id, p.auth_generation, iat).await?;
                }
                Self::session_principal_tx(tx, p).await?;
                let role = Self::authorize_tx(tx, &p.tenant_id, &p.user_id, p.credential_generations()?).await?;
                let mut current = p.clone();
                current.role = role;
                if full {
                    current.require(memoswish_core::Permission::AccountExport)
                } else {
                    current.require(memoswish_core::Permission::FeedRead)?;
                    current.require(memoswish_core::Permission::ContentRead)
                }
            }

            pub(crate) async fn personal_export(
                &self,
                p: &memoswish_core::lifecycle::AccountAuthority,
            ) -> memoswish_core::CoreResult<memoswish_protocol::PersonalAccountExport> {
                use memoswish_core::CoreError;
                use memoswish_protocol::*;
                use sqlx::Row;
                let mut tx = self.lifecycle_tx(&[]).await?;
                let rows =
                    sqlx::query("SELECT tenant_id,role FROM tenant_memberships WHERE user_id=$1 ORDER BY tenant_id")
                        .bind(p.user_id())
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                let tenants: Vec<String> = rows.iter().map(|r| r.get("tenant_id")).collect();
                Self::lifecycle_lock_tenants(&mut tx, &tenants).await?;
                Self::lifecycle_account_authorize(&mut tx, p).await?;
                let row = sqlx::query("SELECT email,display_name FROM users WHERE id=$1")
                    .bind(p.user_id())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let email: String = row.get("email");
                let account =
                    AccountProfile { user_id: p.user_id().into(), email, display_name: row.get("display_name") };

                let now = Self::asset_now(&mut tx).await?;
                let mut workspaces = Vec::new();
                for row in rows {
                    let tenant: String = row.get("tenant_id");
                    let mut data = ExportRows::new();
                    // 不连接活卡，因此 S14 删除后的个人历史同样完整导出。
                    for (table, cols) in [
                        ("personal_favorites", &["user_id", "card_id", "starred", "revision"][..]),
                        ("favorite_operations", &["user_id", "operation_id", "command", "receipt"][..]),
                        (
                            "memory_states",
                            &[
                                "user_id",
                                "card_id",
                                "stability",
                                "difficulty",
                                "reps",
                                "lapses",
                                "exposures",
                                "last_review",
                                "due",
                                "starred",
                                "last_rating",
                            ][..],
                        ),
                        (
                            "feedback_events",
                            &[
                                "user_id",
                                "card_id",
                                "session_id",
                                "rating",
                                "body",
                                "received_at",
                                "application_provenance",
                            ][..],
                        ),
                        (
                            "api_tokens",
                            &["id", "name", "scopes", "created_at", "expires_at", "last_used_at", "revoked"][..],
                        ),
                        ("oauth_grants", &["id", "client_id", "expires_at", "revoked", "metadata"][..]),
                        ("feed_sessions", &["id", "next_slot", "recent_card_ids", "created_at", "updated_at"][..]),
                        ("content_reports", &["body"][..]),
                        ("content_imports", &["id", "outcome", "result"][..]),
                        ("bgm_publications", &["id", "request_id", "track", "outcome", "result"][..]),
                        ("explanation_operations", &["id", "card_id", "state", "period", "result", "context"][..]),
                        ("learner_preferences", &["user_id", "desired_retention", "revision", "epoch", "issuance_seq"][..]),
                        ("learner_card_controls", &["user_id", "card_id", "suspended", "buried_until_ms", "revision", "last_issued_seq"][..]),
                        ("feed_deliveries", &["session_id", "slot", "delivery_id", "body"][..]),
                        ("oidc_attempts", &["provider", "expires_at"][..]),
                        ("oidc_handoffs", &["provider", "expires_at"][..]),
                        ("recent_authentication", &["expires_at"][..]),
                        ("auth_browser_sessions", &["expires_at"][..]),
                    ] {
                        data.insert(
                            table.into(),
                            Self::export_rows(
                                &mut tx,
                                table,
                                cols,
                                "tenant_id=$1 AND user_id=$2",
                                &tenant,
                                p.user_id(),
                            )
                            .await?,
                        );
                    }
                    data.insert("diagnostic_reports".into(), Self::export_rows(&mut tx, "diagnostic_reports", &["report_id","body","created_at_ms","expires_at_ms"], &format!("tenant_id=$1 AND user_id=$2 AND expires_at_ms>{now}"), &tenant, p.user_id()).await?);
                    data.insert(
                        "import_followups".into(),
                        Self::export_rows(
                            &mut tx,
                            "import_followups",
                            &["import_id", "card_id", "revision", "outcome"],
                            "tenant_id=$1 AND import_id IN (SELECT id FROM content_imports WHERE tenant_id=$1 AND user_id=$2)",
                            &tenant,
                            p.user_id(),
                        )
                        .await?,
                    );
                    let members: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id=$1")
                        .bind(&tenant)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    workspaces.push(PersonalWorkspaceExport {
                        tenant_id: tenant,
                        role: row.get("role"),
                        exclusive: members == 1 && row.get::<String, _>("role") == "owner",
                        data,
                    });
                }
                // 历史 tenant hint 不决定全局身份的归属，只按 user_id 读取。
                let rows =
                    sqlx::query("SELECT body FROM federated_identities WHERE user_id=$1 ORDER BY issuer,subject")
                        .bind(p.user_id())
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                let mut identities = Vec::new();
                for row in rows {
                    let identity: memoswish_core::identity::FederatedIdentity =
                        serde_json::from_str(&row.get::<String, _>("body"))
                            .map_err(|_| CoreError::internal("invalid identity export metadata"))?;
                    identities.push(LinkedIdentity {
                        provider: identity.provider,
                        issuer: identity.issuer,
                        subject: identity.subject,
                        email: identity.email,
                    });
                }
                let session_metadata = Self::export_rows(
                    &mut tx,
                    "app_sessions",
                    &["id", "provenance", "auth_time", "expires_at", "revoked"],
                    "$1=$1 AND user_id=$2",
                    "",
                    p.user_id(),
                )
                .await?;
                let account_privacy = Self::export_rows(&mut tx,"privacy_accounts",&["revision","body"],"$1=$1 AND user_id=$2","",p.user_id()).await?;
                let purpose_privacy = Self::export_rows(&mut tx,"privacy_purposes",&["tenant_id","body"],"$1=$1 AND user_id=$2","",p.user_id()).await?;
                let privacy_records=vec![serde_json::json!({"account":account_privacy,"purposes":purpose_privacy})];
                self.lifecycle_commit(tx).await?;
                Ok(PersonalAccountExport {
                    privacy_records,
                    account,
                    identities,
                    workspaces,
                    session_metadata,
                    exported_at: chrono::Utc::now().to_rfc3339(),
                })
            }

            pub(crate) async fn workspace_export(
                &self,
                p: &memoswish_core::Principal,
            ) -> memoswish_core::CoreResult<memoswish_protocol::WorkspaceExport> {
                use memoswish_protocol::*;
                if p.via == "mcp_oauth" {
                    return Err(memoswish_core::CoreError::Forbidden("MCP credentials cannot export workspaces".into()));
                }
                let mut tx = self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                Self::export_workspace_authorize(&mut tx, p, true).await?;
                let editor=p.can(memoswish_core::Permission::ContentWrite) && Self::authorize_tx(&mut tx,&p.tenant_id,&p.user_id,p.credential_generations()?).await?.allows(memoswish_core::Permission::ContentWrite);
                let mut data = ExportRows::new();
                // 工作区导出只包含调用者自己的诊断，owner 不能读取其他成员的诊断。
                let now = Self::asset_now(&mut tx).await?;
                data.insert("diagnostic_reports".into(), Self::export_rows(&mut tx,"diagnostic_reports",&["report_id","body","created_at_ms","expires_at_ms"],&format!("tenant_id=$1 AND user_id=$2 AND expires_at_ms>{now}"),&p.tenant_id,&p.user_id).await?);
                for (table, columns, filter) in [
                    ("tenants", &["id", "name", "plan", "created_at"][..], "id=$1 AND $2=$2"),
                    (
                        "decks",
                        &["id", "title", "description", "language", "tags", "created_at"][..],
                        "tenant_id=$1 AND $2=$2",
                    ),
                    ("cards", &["body"][..], "tenant_id=$1 AND $2=$2"),
                    ("content_revisions", &["body"][..], "tenant_id=$1 AND $2=$2"),
                    ("content_reports", &["body"][..], "tenant_id=$1 AND $2=$2"),
                    ("bgm_tracks", &["body"][..], "tenant_id=$1 AND $2=$2"),
                    ("bgm_publications", &["id", "user_id", "request_id", "track", "outcome", "result"][..], "tenant_id=$1 AND $2=$2"),
                    ("content_imports", &["id", "user_id", "outcome", "result"][..], "tenant_id=$1 AND $2=$2"),
                    (
                        "explanation_operations",
                        &["id", "user_id", "card_id", "state", "period", "result", "context"][..],
                        "tenant_id=$1 AND user_id=$2",
                    ),
                    (
                        "import_followups",
                        &["import_id", "card_id", "revision", "outcome"][..],
                        "tenant_id=$1 AND $2=$2",
                    ),
                    ("usage_counters", &["metric", "period", "amount"][..], "tenant_id=$1 AND $2=$2"),
                    (
                        "tts_submission_items",
                        &["item_id", "receipt"][..],
                        "tenant_id=$1 AND $2=$2 AND receipt IS NOT NULL",
                    ),
                ] {
                    let filter=if editor {filter}else{match table {
                        "cards"=>"tenant_id=$1 AND $2=$2 AND publication='published'",
                        "content_revisions"=>"tenant_id=$1 AND $2=$2 AND 1=0",
                        "content_reports"=>"tenant_id=$1 AND user_id=$2",
                        _=>filter,
                    }};
                    data.insert(
                        table.into(),
                        Self::export_rows(&mut tx, table, columns, filter, &p.tenant_id, &p.user_id).await?,
                    );
                }
                self.lifecycle_commit(tx).await?;
                Ok(WorkspaceExport {
                    tenant_id: p.tenant_id.clone(),
                    data,
                    assets: Vec::new(),
                    exported_at: chrono::Utc::now().to_rfc3339(),
                })
            }
        }
    };
}
pub(crate) use account_export_impl;
