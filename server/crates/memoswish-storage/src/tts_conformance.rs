//! 同一验收场景在 SQLite 和 PostgreSQL 运行，含真实独立连接与故障事务。
use crate::asset_conformance::seed;
use memoswish_core::assets::*;
use memoswish_core::identity::IdentityRepo;
use memoswish_core::lifecycle::LifecycleRepo;
use memoswish_core::repo::*;
use memoswish_core::tts::*;
use memoswish_core::{CoreError, Principal, Role};

#[path = "tts_submission_conformance.rs"]
mod submissions;

fn work() -> SpeechWork {
    SpeechWork {
        provenance: None,
        privacy: None,
        engine: "test".into(),
        namespace: "config".into(),
        request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
        amount: 3,
        legacy_output: None,
    }
}
fn metadata() -> SpeechMetadata {
    SpeechMetadata {
        alignment_quality: None,
        audio_kind: None,
        provenance: None,
        extension: "mp3".into(),
        duration_ms: 100,
        words: vec![],
    }
}
fn spec() -> AssetSpec {
    AssetSpec { mime: "audio/mpeg".into(), size: 3, sha256: memoswish_core::ids::sha256_hex(b"abc") }
}
async fn materialize(repo: &impl Repository, p: &Principal, r: &SpeechRequest) {
    let c = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
    repo.begin_provider(&p.tenant_id, &c).await.unwrap();
    repo.materialize_speech(&p.tenant_id, &c, b"abc", &spec(), &metadata(), false).await.unwrap();
}
async fn publish(repo: &impl Repository, p: &Principal, r: &SpeechRequest) {
    let (upload, bytes) = repo.speech_upload(&p.tenant_id, &r.synthesis_id).await.unwrap().unwrap();
    assert_eq!(bytes, b"abc");
    let c = repo.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().unwrap();
    let a = repo.begin_upload(&p.tenant_id, &c, "store").await.unwrap();
    repo.record_upload(&p.tenant_id, &a, &ObjectVersion::VersionId("null".into())).await.unwrap();
    repo.publish_speech(&p.tenant_id, &c, &a.id).await.unwrap();
    assert!(repo.publish_speech(&p.tenant_id, &c, &a.id).await.is_err());
}

async fn sharing(repo: &impl Repository, other: &impl Repository) {
    let p = seed(repo).await;
    let w = work();
    let barrier = tokio::sync::Barrier::new(2);
    let (a, b) = tokio::join!(
        async {
            barrier.wait().await;
            repo.accept_speech(&p, &w, None, Some(3)).await
        },
        async {
            barrier.wait().await;
            other.accept_speech(&p, &w, None, Some(3)).await
        }
    );
    let r = a.unwrap();
    assert_eq!(r, b.unwrap());
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3, 0));
    let mut w2 = w.clone();
    w2.request.voice = "other".into();
    assert!(matches!(repo.accept_speech(&p, &w2, None, Some(3)).await, Err(CoreError::QuotaExceeded(_))));
    let peer = seed(repo).await;
    let peer_work = repo.accept_speech(&peer, &w, None, Some(3)).await.unwrap();
    assert_ne!(peer_work.synthesis_id, r.synthesis_id);
    assert!(repo.speech_work(&peer.tenant_id, &r.synthesis_id).await.is_err());
    materialize(repo, &p, &r).await;
    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3, 0));
    publish(repo, &p, &r).await;
    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (0, 0));
    assert_eq!(repo.get_usage(&p.tenant_id, "tts_chars", &period).await.unwrap(), 3);
    let replay = other.accept_speech(&p, &w, None, Some(3)).await.unwrap();
    assert_eq!(replay.synthesis_id, r.synthesis_id);
    assert_eq!(replay.outcome, "published");
    assert_eq!(repo.speech_track(&p.tenant_id, &r.synthesis_id).await.unwrap().unwrap().audio.mime, "audio/mpeg");
    // 原请求者被撤销不会取消共享结果，另一个当前成员仍可获取引用。
    let mut member = seed(repo).await;
    repo.membership_join(&p.tenant_id, &member.user_id, Role::Editor).await.unwrap();
    member.tenant_id = p.tenant_id.clone();
    member.role = Role::Editor;
    let m = repo.accept_speech(&member, &w, None, Some(3)).await.unwrap();
    assert_eq!(m.synthesis_id, r.synthesis_id);
    assert_ne!(m.id, r.id);
}

async fn lifecycle_requesters(repo: &impl Repository) {
    use crate::lifecycle_conformance::{account, member, workspace};
    use memoswish_core::lifecycle::{CloseAccount, TransferOwnership};
    for phase in ["pending", "published"] {
        for change in ["leave", "close", "transfer"] {
            let owner = workspace(repo).await;
            let editor = member(repo, &owner.tenant_id, Role::Editor).await;
            let requester = if change == "transfer" { &owner } else { &editor };
            let deck = memoswish_protocol::examples::sample_deck();
            let mut card = memoswish_protocol::examples::sample_card();
            card.tts = None;
            repo.insert_deck_with_cards(&owner.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
            let r = repo.accept_speech(requester, &work(), Some((&card.id, card.revision)), None).await.unwrap();
            // 生命周期夹具的旧 JWT 只提供 iat；新自动提交还需要原始到期证据。
            let durable_requester = if requester.via == "jwt" {
                Principal {
                    session_access_hash: Some(format!("jwt:{}", chrono::Utc::now().timestamp() + 3600)),
                    ..requester.clone()
                }
            } else {
                requester.clone()
            };
            let submission = repo
                .submit_speech(
                    &durable_requester,
                    "lifecycle",
                    &"a".repeat(64),
                    &[SpeechSubmissionTarget { card_id: card.id.clone(), revision: card.revision, work: work() }],
                    None,
                )
                .await
                .unwrap();
            let item = &submission.items[0].item_id;
            materialize(repo, &owner, &r).await;
            if phase == "published" {
                publish(repo, &owner, &r).await;
            }
            match change {
                "leave" => {
                    repo.leave_workspace(requester).await.unwrap();
                }
                "close" => {
                    repo.close_account(&account(requester), &CloseAccount::default()).await.unwrap();
                }
                _ => {
                    repo.transfer_ownership(&owner, &TransferOwnership { successor_user_id: editor.user_id.clone() })
                        .await
                        .unwrap();
                }
            }
            assert_eq!(repo.speech_request(&owner.tenant_id, &r.id).await.unwrap().outcome, "requester_revoked");
            let resolution = repo.resolve_speech_attachment(&owner.tenant_id, item).await;
            if change == "transfer" {
                resolution.unwrap();
            } else {
                assert!(matches!(resolution, Err(CoreError::NotFound(_))));
            }
            assert_eq!(repo.speech_request(&owner.tenant_id, item).await.unwrap().outcome, "requester_revoked");
            assert!(
                !repo
                    .pending_speech_attachments(Some((&owner.tenant_id, "")), 100)
                    .await
                    .unwrap()
                    .contains(&(owner.tenant_id.clone(), item.clone()))
            );
            assert!(repo.speech_submission(&durable_requester, "lifecycle", None).await.is_err());

            // 新的有效成员仍可复用共享结果；撤销的能力不因重加入或角色提升而恢复。
            let current = if change == "transfer" {
                Principal { role: Role::Owner, membership_generation: Some(1), ..editor.clone() }
            } else {
                owner.clone()
            };
            let peer = repo.accept_speech(&current, &work(), None, None).await.unwrap();
            assert_eq!(peer.synthesis_id, r.synthesis_id);
            if phase == "pending" {
                publish(repo, &owner, &r).await;
            }
            if change == "leave" {
                repo.membership_join(&owner.tenant_id, &requester.user_id, Role::Editor).await.unwrap();
            }
            assert!(matches!(repo.attach_speech(&owner.tenant_id, &r.id).await, Err(CoreError::Forbidden(_))));
            assert!(repo.accept_speech(requester, &work(), None, None).await.is_err());
            assert_eq!(repo.get_card(&owner.tenant_id, &card.id).await.unwrap().unwrap(), card);
            assert_eq!(repo.speech_request(&owner.tenant_id, &peer.id).await.unwrap().outcome, "published");
        }
    }
}

macro_rules! suite {
    ($repo:ty,$pool:ty,$sqlite:literal,$migrations:literal) => {
        submissions::faults!($repo,$sqlite);
        async fn s6_receipt_lifecycle(repo: &$repo) {
            use sqlx::Row;
            use crate::lifecycle_conformance::{account, confirmation, member, workspace};
            use memoswish_core::lifecycle::{CloseAccount, TransferOwnership};
            for phase in ["uncertain", "materialized", "published"] {
                let terminal = phase == "published";
                for change in ["leave", "close", "delete", "legacy", "internal_owner", "internal_member", "transfer"] {
                    let owner = workspace(repo).await;
                    let editor = member(repo, &owner.tenant_id, Role::Editor).await;
                    let requester = if matches!(change, "delete" | "legacy" | "internal_owner" | "transfer") { &owner } else { &editor };
                    let durable = Principal {
                        session_access_hash: Some(format!("jwt:{}", chrono::Utc::now().timestamp() + 3600)),
                        ..requester.clone()
                    };
                    let targets = submissions::targets(repo, &durable, 1).await;
                    let submission = repo.submit_speech(&durable, "S6_MINIMAL_RECEIPT", &"a".repeat(64), &targets, None).await.unwrap();
                    let item = &submission.items[0].item_id;
                    let request = repo.speech_request(&owner.tenant_id, item).await.unwrap();
                    if phase != "uncertain" {
                        materialize(repo, &owner, &request).await;
                    }
                    if terminal {
                        publish(repo, &owner, &request).await;
                        repo.resolve_speech_attachment(&owner.tenant_id, item).await.unwrap();
                    } else if phase == "uncertain" {
                        let claim = repo.claim_speech(&owner.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
                        repo.begin_provider(&owner.tenant_id, &claim).await.unwrap();
                    }
                    let export = repo.export_workspace(&owner).await.unwrap();
                    let receipts = &export.data["tts_submission_items"];
                    assert_eq!(receipts.len(), usize::from(terminal));
                    if terminal {
                        assert_eq!(receipts[0]["receipt"], serde_json::to_value(repo.speech_submission(&durable, "S6_MINIMAL_RECEIPT", None).await.unwrap().unwrap().items[0].receipt.as_ref().unwrap()).unwrap());
                        assert_eq!(receipts[0].as_object().unwrap().len(), 2);
                        for secret in ["user_id", "command_hash", "session_access_hash", "credential_via", "legacy_issued_at", "S6_MINIMAL_RECEIPT"] {
                            assert!(!serde_json::to_string(receipts).unwrap().contains(secret));
                        }
                    }
                    let peer = if requester.user_id == owner.user_id { &editor } else { &owner };
                    let peer_durable = Principal { session_access_hash: Some(format!("jwt:{}", chrono::Utc::now().timestamp() + 3600)), ..peer.clone() };
                    let peer_targets = submissions::targets(repo, &peer_durable, 1).await;
                    repo.submit_speech(&peer_durable, "S6_PEER", &"b".repeat(64), &peer_targets, None).await.unwrap();
                    let foreign = workspace(repo).await;
                    let foreign_durable = Principal { session_access_hash: Some(format!("jwt:{}", chrono::Utc::now().timestamp() + 3600)), ..foreign.clone() };
                    let foreign_targets = submissions::targets(repo, &foreign_durable, 1).await;
                    repo.submit_speech(&foreign_durable, "S6_FOREIGN", &"c".repeat(64), &foreign_targets, None).await.unwrap();
                    let mut evidence = Vec::new();
                    for table in ["tts_syntheses", "tts_provider_attempts", "asset_upload_attempts", "quota_operations", "background_jobs"] {
                        let filter = if table == "background_jobs" { " AND kind<>'erasure'" } else { "" };
                        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1{filter}")).bind(&owner.tenant_id).fetch_one(repo.pool()).await.unwrap();
                        evidence.push((table, count));
                    }
                    match change {
                        "leave" => repo.leave_workspace(requester).await.unwrap(),
                        "close" => { repo.close_account(&account(requester), &CloseAccount::default()).await.unwrap(); },
                        "delete" => { repo.delete_workspace(&owner, &confirmation(&owner)).await.unwrap(); },
                        "legacy" => { repo.legacy_close_account(&owner).await.unwrap(); },
                        "internal_owner" => { repo.account_erase(&owner.tenant_id,&owner.user_id,true).await.unwrap(); },
                        "internal_member" => { repo.account_erase(&owner.tenant_id,&requester.user_id,false).await.unwrap(); },
                        _ => repo.transfer_ownership(&owner, &TransferOwnership { successor_user_id: editor.user_id.clone() }).await.unwrap(),
                    }
                    for table in ["tts_submission_items", "tts_submissions"] {
                        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1 AND user_id=$2")).bind(&owner.tenant_id).bind(&requester.user_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(count, i64::from(change == "transfer"), "{change}: {table}");
                        let peer_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1 AND user_id=$2")).bind(&owner.tenant_id).bind(&peer.user_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(peer_count, i64::from(!matches!(change, "delete" | "legacy" | "internal_owner")), "{change}: {table}");
                        let foreign_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1")).bind(&foreign.tenant_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(foreign_count, 1);
                    }
                    for (table, count) in evidence {
                        let filter = if table == "background_jobs" { " AND kind<>'erasure'" } else { "" };
                        let retained: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1{filter}")).bind(&owner.tenant_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(retained, count, "{change}: {table}");
                    }
                    if matches!(change, "delete" | "legacy" | "internal_owner") {
                        use memoswish_core::erasure::ErasureRepo;
                        // 擦除清空正文及音频，但未决 provider 和预留费用继续由原记录承担。
                        let row = sqlx::query("SELECT work,audio,metadata FROM tts_syntheses WHERE tenant_id=$1 AND id=$2").bind(&owner.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(row.get::<String,_>("work"), "{}");
                        assert!(row.get::<Option<Vec<u8>>,_>("audio").is_none());
                        assert!(row.get::<Option<String>,_>("metadata").is_none());
                        let state: String = sqlx::query_scalar("SELECT state FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2").bind(&owner.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(state, if terminal { "committed" } else { "reserved" });
                        let job = repo.account_erasure_jobs().await.unwrap().into_iter().find(|j|j.tenant_id.as_deref()==Some(&owner.tenant_id) && j.purge_assets).unwrap();
                        let claim = repo.claim_erasure(&job.id,"s19-tts",30_000).await.unwrap().unwrap();
                        for object in repo.erasure_objects(&claim,("",""),100).await.unwrap() {
                            repo.begin_erasure_object(&claim,&object,"store").await.unwrap();
                            repo.record_erasure_object(&object).await.unwrap();
                        }
                        repo.acknowledge_erasure_assets(&claim).await.unwrap();
                        if phase == "uncertain" {
                            assert!(repo.complete_erasure(&claim).await.is_err());
                            repo.retry_erasure(&claim).await.unwrap();
                            assert_eq!(repo.erasure_work(&job.id).await.unwrap().unwrap().progress,"blocked");
                        } else {
                            repo.complete_erasure(&claim).await.unwrap();
                        }
                        let retained: String = sqlx::query_scalar("SELECT state FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2").bind(&owner.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(retained,state);
                    }
                    assert_eq!(repo.speech_request(&owner.tenant_id, item).await.unwrap().outcome, "requester_revoked");
                    if change != "transfer" {
                        assert!(matches!(repo.resolve_speech_attachment(&owner.tenant_id, item).await, Err(CoreError::NotFound(_))));
                    }
                }
            }
        }
        async fn s17_credentials(repo:&$repo) {
            use memoswish_core::oauth::*;
            use memoswish_core::session::SessionRepo;
            use memoswish_core::principal::CredentialGenerations;
            let scopes=vec!["tts:generate".to_string(),"content:read".to_string(),"content:write".to_string()];
            for via in ["api_token","mcp_oauth"] {
                for phase in ["admission","pending","publication","attachment"] {
                    for change in ["revoke","expiry","scope","missing","logout_all"] {
                        let p=seed(repo).await;
                        let hash=memoswish_core::ids::new_id();let token_id=memoswish_core::ids::new_id();
                        let mut delegated=p.clone();delegated.via=via.into();delegated.scopes=Some(scopes.clone());
                        if via=="api_token" {
                            repo.insert_api_token(&memoswish_core::repo::ApiTokenRecord{id:token_id.clone(),tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),name:"S17".into(),token_hash:hash.clone(),generations:CredentialGenerations{account:0,membership:0},scopes:scopes.clone(),created_at:chrono::Utc::now(),expires_at:Some(chrono::Utc::now()+chrono::Duration::hours(1)),last_used_at:None,revoked:false}).await.unwrap();
                            delegated.session_access_hash=Some(format!("api:{hash}"));
                        } else {
                            let expiry=chrono::Utc::now().timestamp()+3600;
                            let client=OAuthClient{id:memoswish_core::ids::new_id(),name:"S17".into(),redirect_uris:vec!["https://example.com/cb".into()],grant_types:vec!["authorization_code".into()],scopes:scopes.clone(),auth_method:"none".into(),secret_hash:None,created_at:expiry-3600,expires_at:expiry};
                            repo.oauth_register(&client).await.unwrap();
                            let grant=OAuthGrant{generations:CredentialGenerations{account:0,membership:0},id:token_id.clone(),tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),client_id:client.id.clone(),resource:"https://example.com/mcp".into(),scopes:scopes.clone(),expires_at:expiry};
                            let token=OAuthToken{hash:hash.clone(),grant,scopes:scopes.clone(),kind:"access".into(),expires_at:expiry};
                            sqlx::query("INSERT INTO oauth_grants(id,tenant_id,user_id,client_id,expires_at) VALUES($1,$2,$3,$4,$5)").bind(&token_id).bind(&p.tenant_id).bind(&p.user_id).bind(&client.id).bind(expiry).execute(repo.pool()).await.unwrap();
                            sqlx::query("INSERT INTO oauth_tokens(hash,tenant_id,grant_id,kind,expires_at,body) VALUES($1,$2,$3,'access',$4,$5)").bind(&hash).bind(&p.tenant_id).bind(&token_id).bind(expiry).bind(serde_json::to_string(&token).unwrap()).execute(repo.pool()).await.unwrap();
                            delegated.session_access_hash=Some(format!("oauth:{hash}"));
                        }
                        let ts=submissions::targets(repo,&p,1).await;
                        let accepted=if phase=="admission"{None}else{Some(repo.submit_speech(&delegated,"credential",&"a".repeat(64),&ts,None).await.unwrap())};
                        let requester=if let Some(a)=&accepted {Some(repo.speech_request(&p.tenant_id,&a.items[0].item_id).await.unwrap())}else{None};
                        if let Some(r)=&requester {
                            if phase!="pending" {materialize(repo,&p,r).await;}
                            if phase=="attachment" {publish(repo,&p,r).await;}
                        }
                        if change=="logout_all" {
                            // App 全端注销不能扩大到 API Token 或 MCP grant 的撤销域。
                            let now=chrono::Utc::now().timestamp();
                            let family=memoswish_core::session::SessionFamily{id:memoswish_core::ids::new_id(),user_id:p.user_id.clone(),generation:0,provenance:"password".into(),auth_time:now,expires_at:now+3600,revoked:false};
                            let root=crate::session_conformance::credential(&family,None);
                            repo.session_issue(&family,&root,None).await.unwrap();
                            repo.session_revoke_all(&root.access_hash).await.unwrap();
                        } else if via=="api_token" {
                            match change {
                                "revoke"=>{repo.revoke_api_token(&p.tenant_id,&token_id).await.unwrap();},
                                "expiry"=>{sqlx::query("UPDATE api_tokens SET expires_at=$2 WHERE token_hash=$1").bind(&hash).bind(chrono::Utc::now()-chrono::Duration::hours(1)).execute(repo.pool()).await.unwrap();},
                                "scope"=>{sqlx::query("UPDATE api_tokens SET scopes=$2 WHERE token_hash=$1").bind(&hash).bind(sqlx::types::Json(vec!["content:read"])).execute(repo.pool()).await.unwrap();},
                                _=>{sqlx::query("DELETE FROM api_tokens WHERE token_hash=$1").bind(&hash).execute(repo.pool()).await.unwrap();},
                            }
                        } else {
                            match change {
                                "revoke"=>repo.oauth_revoke(&p.tenant_id,&token_id).await.unwrap(),
                                "expiry"=>{sqlx::query("UPDATE oauth_tokens SET expires_at=0 WHERE hash=$1").bind(&hash).execute(repo.pool()).await.unwrap();},
                                "scope"=>{
                                    let body:String=sqlx::query_scalar("SELECT body FROM oauth_tokens WHERE hash=$1").bind(&hash).fetch_one(repo.pool()).await.unwrap();
                                    let mut token:OAuthToken=serde_json::from_str(&body).unwrap();token.scopes=vec!["content:read".into()];
                                    sqlx::query("UPDATE oauth_tokens SET body=$2 WHERE hash=$1").bind(&hash).bind(serde_json::to_string(&token).unwrap()).execute(repo.pool()).await.unwrap();
                                },
                                _=>{sqlx::query("DELETE FROM oauth_tokens WHERE hash=$1").bind(&hash).execute(repo.pool()).await.unwrap();},
                            }
                        }
                        if let Some(r)=requester {
                            if phase=="pending" && change=="logout_all" {materialize(repo,&p,&r).await;}
                            if phase=="publication" || (phase=="pending" && change=="logout_all") {publish(repo,&p,&r).await;}
                            repo.resolve_speech_attachment(&p.tenant_id,&r.id).await.unwrap();
                            let status=repo.speech_submission(&p,"credential",None).await.unwrap().unwrap();
                            assert!(status.complete);
                            let expected=if change=="logout_all" {memoswish_protocol::TtsDisposition::Attached}else{memoswish_protocol::TtsDisposition::RequesterRevoked};
                            assert_eq!(status.items[0].receipt.as_ref().unwrap().disposition,expected);
                            assert_eq!(repo.get_card(&p.tenant_id,&ts[0].card_id).await.unwrap().unwrap().tts.is_some(),change=="logout_all");
                        }
                        let replay=repo.submit_speech(&delegated,"credential",&"a".repeat(64),&ts,None).await;
                        if change=="logout_all" {assert!(replay.is_ok());}
                        else {assert!(matches!(replay,Err(CoreError::Forbidden(_))));}
                    }
                }
            }
            // 原 session 旋转后不能执行，后继只读原始最小事实，重放不重授权。
            let p=seed(repo).await;
            let now=chrono::Utc::now().timestamp();
            let family=memoswish_core::session::SessionFamily{id:memoswish_core::ids::new_id(),user_id:p.user_id.clone(),generation:0,provenance:"password".into(),auth_time:now,expires_at:now+3600,revoked:false};
            let credential=crate::session_conformance::credential(&family,Some((p.tenant_id.clone(),0)));
            repo.session_issue(&family,&credential,None).await.unwrap();
            let old=Principal{via:"session".into(),session_access_hash:Some(credential.access_hash.clone()),..p.clone()};
            let ts=submissions::targets(repo,&p,1).await;
            let accepted=repo.submit_speech(&old,"rotated",&"a".repeat(64),&ts,None).await.unwrap();
            let r=repo.speech_request(&p.tenant_id,&accepted.items[0].item_id).await.unwrap();
            materialize(repo,&p,&r).await;publish(repo,&p,&r).await;
            let next=memoswish_core::ids::new_id();
            repo.session_rotate(&credential.refresh_hash,&next,&memoswish_core::ids::new_id(),&memoswish_core::ids::new_id(),600).await.unwrap();
            repo.resolve_speech_attachment(&p.tenant_id,&r.id).await.unwrap();
            let successor=Principal{session_access_hash:Some(next),..old.clone()};
            let terminal=repo.speech_submission(&successor,"rotated",None).await.unwrap().unwrap();
            assert!(terminal.complete);
            assert_eq!(terminal.items[0].receipt.as_ref().unwrap().disposition,memoswish_protocol::TtsDisposition::RequesterRevoked);
            assert_eq!(repo.submit_speech(&successor,"rotated",&"a".repeat(64),&[],None).await.unwrap(),terminal);
            assert!(repo.speech_submission(&old,"rotated",None).await.is_err());
            let p=seed(repo).await;
            let now=chrono::Utc::now().timestamp();
            let jwt=Principal{via:"jwt".into(),legacy_issued_at:Some(now),session_access_hash:Some(format!("jwt:{}",now+3600)),..p.clone()};
            let ts=submissions::targets(repo,&p,1).await;
            let expired=Principal{session_access_hash:Some("jwt:0".into()),..jwt.clone()};
            assert!(repo.submit_speech(&expired,"jwt-expiry",&"a".repeat(64),&ts,None).await.is_err());
            let accepted=repo.submit_speech(&jwt,"jwt-expiry",&"a".repeat(64),&ts,None).await.unwrap();
            let r=repo.speech_request(&p.tenant_id,&accepted.items[0].item_id).await.unwrap();
            materialize(repo,&p,&r).await;publish(repo,&p,&r).await;
            sqlx::query("UPDATE tts_requesters SET session_access_hash='jwt:0' WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&r.id).execute(repo.pool()).await.unwrap();
            repo.resolve_speech_attachment(&p.tenant_id,&r.id).await.unwrap();
            assert_eq!(repo.speech_submission(&jwt,"jwt-expiry",None).await.unwrap().unwrap().items[0].receipt.as_ref().unwrap().disposition,memoswish_protocol::TtsDisposition::RequesterRevoked);

        }

        async fn s17_app_session_fences(repo: &$repo) {
            use memoswish_core::session::{SessionFamily, SessionRepo};
            use memoswish_protocol::TtsDisposition;
            for via in ["session", "jwt", "legacy_jwt"] {
                for phase in ["admission", "pending", "publication", "attachment"] {
                    let p = seed(repo).await;
                    let now = chrono::Utc::now().timestamp();
                    let family = SessionFamily {
                        id: memoswish_core::ids::new_id(), user_id: p.user_id.clone(), generation: 0,
                        provenance: "password".into(), auth_time: now - 10, expires_at: now + 3600, revoked: false,
                    };
                    let root = crate::session_conformance::credential(&family, None);
                    repo.session_issue(&family, &root, None).await.unwrap();
                    let access = crate::session_conformance::credential(&family, Some((p.tenant_id.clone(), 0)));
                    repo.session_select(&root.access_hash, &access).await.unwrap();
                    let captured = if via == "session" {
                        Principal { via: "session".into(), session_access_hash: Some(access.access_hash), ..p.clone() }
                    } else {
                        Principal { via: "jwt".into(), session_access_hash: Some(format!("jwt:{}", now + 3600)), legacy_issued_at: Some(family.auth_time), ..p.clone() }
                    };
                    let targets = submissions::targets(repo, &p, 1).await;
                    let card = repo.get_card(&p.tenant_id, &targets[0].card_id).await.unwrap().unwrap();
                    let request = if phase == "admission" { None } else {
                        let accepted = repo.submit_speech(&captured, "app-fence", &"a".repeat(64), &targets, None).await.unwrap();
                        let request = repo.speech_request(&p.tenant_id, &accepted.items[0].item_id).await.unwrap();
                        if via == "legacy_jwt" {
                            // 升级前的请求者没有来源列，原始 iat 仍须参与屏障复核。
                            sqlx::query("UPDATE tts_requesters SET credential_via='legacy' WHERE tenant_id=$1 AND id=$2")
                                .bind(&p.tenant_id).bind(&request.id).execute(repo.pool()).await.unwrap();
                        }
                        if phase != "pending" { materialize(repo, &p, &request).await; }
                        if phase == "attachment" { publish(repo, &p, &request).await; }
                        Some(request)
                    };
                    // 使用真实账户根 access 提交注销，捕获的工作区凭据随后进入事务。
                    repo.session_revoke_all(&root.access_hash).await.unwrap();
                    assert!(matches!(repo.submit_speech(&captured, "app-fence", &"a".repeat(64), &targets, None).await, Err(CoreError::Forbidden(_))));
                    assert!(matches!(repo.speech_submission(&captured, "app-fence", None).await, Err(CoreError::Forbidden(_))));
                    if let Some(request) = request {
                        if phase == "publication" { publish(repo, &p, &request).await; }
                        repo.resolve_speech_attachment(&p.tenant_id, &request.id).await.unwrap();
                        let status = repo.speech_submission(&p, "app-fence", None).await.unwrap().unwrap();
                        assert!(status.complete);
                        assert_eq!(status.items[0].receipt.as_ref().unwrap().disposition, TtsDisposition::RequesterRevoked);
                        assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
                        let references: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id=$1 AND owner_id=$2 AND slot='tts_card'")
                            .bind(&p.tenant_id).bind(&card.id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(references, 0);
                        repo.resolve_speech_attachment(&p.tenant_id, &request.id).await.unwrap();
                        assert_eq!(repo.speech_submission(&p, "app-fence", None).await.unwrap().unwrap(), status);
                    }
                    let fence: i64 = sqlx::query_scalar("SELECT revoked_through FROM app_session_fences WHERE user_id=$1")
                        .bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
                    for iat in [None, Some(fence - 1), Some(fence), Some(fence + 1)] {
                        let jwt = Principal { via: "jwt".into(), session_access_hash: Some(format!("jwt:{}", now + 3600)), legacy_issued_at: iat, ..p.clone() };
                        let result = repo.submit_speech(&jwt, "after-fence", &"b".repeat(64), &targets, None).await;
                        assert_eq!(result.is_ok(), iat == Some(fence + 1));
                    }
                    // 本地模式保留自己的授权域，仍需通过同一事务的角色和世代检查。
                    for local_via in ["single_user", "stdio"] {
                        let local = Principal { via: local_via.into(), ..p.clone() };
                        assert!(repo.submit_speech(&local, local_via, &"c".repeat(64), &targets, None).await.is_ok());
                    }
                }
            }
        }

        async fn s17_upgrade(pool:&$pool) {
            use crate::foundation_conformance::{through,LEGACY_DATA};
            let full=sqlx::migrate!($migrations);
            through(&full,8).run(pool).await.unwrap();sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();through(&full,22).run(pool).await.unwrap();
            let work=serde_json::to_string(&work()).unwrap();
            sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES('foundation','s17-legacy','tts_synthesis','s17-legacy',$1,5,100)").bind(sqlx::types::Json(serde_json::json!({}))).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO tts_syntheses(tenant_id,id,work) VALUES('foundation','s17-legacy',$1)").bind(&work).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO quota_operations(tenant_id,operation_id,metric,period,amount,state) VALUES('foundation','s17-legacy','tts_chars','2026-11',3,'reserved')").execute(pool).await.unwrap();
            sqlx::query("INSERT INTO tts_requesters(tenant_id,id,synthesis_id,user_id,account_generation,membership_generation,content_permission,card_id,revision) VALUES('foundation','s17-legacy-request','s17-legacy','account',7,7,1,'legacy-card',1)").execute(pool).await.unwrap();
            let mut broken=through(&full,23);let index=broken.migrations.len()-1;let m=&broken.migrations[index];
            broken.migrations.to_mut()[index]=sqlx::migrate::Migration::new(m.version,"injected".into(),sqlx::migrate::MigrationType::Simple,format!("{}\nSELECT * FROM s17_injected_missing;",m.sql).into(),false);
            assert!(broken.run(pool).await.is_err());
            assert!(sqlx::query("SELECT * FROM tts_submission_items").fetch_all(pool).await.is_err());
            let stored:String=sqlx::query_scalar("SELECT work FROM tts_syntheses WHERE tenant_id='foundation' AND id='s17-legacy'").fetch_one(pool).await.unwrap();assert_eq!(stored,work);
            let applied:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();assert_eq!(applied,22);
            full.run(pool).await.unwrap();full.run(pool).await.unwrap();
            let classification:String=sqlx::query_scalar("SELECT credential_via FROM tts_requesters WHERE tenant_id='foundation' AND id='s17-legacy-request'").fetch_one(pool).await.unwrap();assert_eq!(classification,"legacy");
            let receipts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tts_submission_items").fetch_one(pool).await.unwrap();assert_eq!(receipts,0);
            let held:i64=sqlx::query_scalar("SELECT amount FROM quota_operations WHERE tenant_id='foundation' AND operation_id='s17-legacy' AND state='reserved'").fetch_one(pool).await.unwrap();assert_eq!(held,3);
        }

        async fn upgrade(pool:&$pool){
            use crate::foundation_conformance::{through,LEGACY_DATA};
            use sqlx::Row;
            let full=sqlx::migrate!($migrations);
            let target=full.iter().find(|m| m.description == "tts publication").expect("S16 migration").version;
            let previous=full.iter().filter(|m| m.version < target).map(|m|m.version).max().unwrap();
            through(&full,8).run(pool).await.unwrap();sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();through(&full,previous).run(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','s16-preserved','tts','s16-preserved','{}','account',7,3,100); INSERT INTO quota_operations VALUES('foundation','s16-preserved','tts_chars','2026-11',17,'reserved');").execute(pool).await.unwrap();
            let body: String=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id='foundation' LIMIT 1").fetch_one(pool).await.unwrap();
            let mut broken=through(&full,target);let index=broken.migrations.len()-1;let m=&broken.migrations[index];
            let sql=format!("{}\nSELECT * FROM s16_injected_missing_table;",m.sql);let version=m.version;
            broken.migrations.to_mut()[index]=sqlx::migrate::Migration::new(version,"injected failure".into(),sqlx::migrate::MigrationType::Simple,sql.into(),false);
            assert!(broken.run(pool).await.is_err());
            let applied:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();assert_eq!(applied,previous);
            assert!(sqlx::query("SELECT id FROM tts_syntheses").fetch_all(pool).await.is_err());
            full.run(pool).await.unwrap();full.run(pool).await.unwrap();
            let after:String=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id='foundation' LIMIT 1").fetch_one(pool).await.unwrap();assert_eq!(body,after);
            let q=sqlx::query("SELECT amount,state FROM quota_operations WHERE tenant_id='foundation' AND operation_id='s16-preserved'").fetch_one(pool).await.unwrap();assert_eq!(q.get::<i64,_>("amount"),17);assert_eq!(q.get::<String,_>("state"),"reserved");
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tts_syntheses").fetch_one(pool).await.unwrap();assert_eq!(count,0);
        }
        async fn attachments(repo:&$repo){
            for change in ["edit","bgm","delete","delete_deck","delete_pending","demote","remove_rejoin","epoch"] {
                let p=seed(repo).await;let deck=memoswish_protocol::examples::sample_deck();let mut card=memoswish_protocol::examples::sample_card();card.tts=None;repo.insert_deck_with_cards(&p.tenant_id,&deck,std::slice::from_ref(&card)).await.unwrap();
                let mut scoped=p.clone();scoped.scopes=Some(vec!["tts:generate".into(),"content:read".into(),"content:write".into()]);
                let r=repo.accept_speech(&scoped,&work(),Some((&card.id,card.revision)),None).await.unwrap();materialize(repo,&p,&r).await;
                if change == "delete_pending" {repo.delete_deck(&p.tenant_id,&deck.id).await.unwrap();}
                publish(repo,&p,&r).await;
                match change {
                    "edit"=>{repo.mutate_cards(&p.tenant_id,&[crate::content_conformance::edit(&card,Some(card.revision),"newer")]).await.unwrap();},
                    "bgm"=>{repo.mutate_cards(&p.tenant_id,&[memoswish_core::content::CardMutation::Bgm{id:card.id.clone(),expected_revision:Some(card.revision),binding:None}]).await.unwrap();},
                    "delete"=>{repo.delete_card_if_revision(&p.tenant_id,&card.id,Some(card.revision)).await.unwrap();},
                    "delete_deck"=>{repo.delete_deck(&p.tenant_id,&deck.id).await.unwrap();},
                    "delete_pending"=>{},
                    "demote"=>{sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();},
                    "epoch"=>{sqlx::query("UPDATE account_auth_epochs SET generation=generation+1 WHERE user_id=$1").bind(&p.user_id).execute(repo.pool()).await.unwrap();},
                    _=>{repo.membership_remove(&p.tenant_id,&p.user_id).await.unwrap();assert_eq!(repo.membership_join(&p.tenant_id,&p.user_id,Role::Owner).await.unwrap(),1);},
                }
                let err=repo.attach_speech(&p.tenant_id,&r.id).await.unwrap_err();
                assert_eq!(err.code(),match change{"edit"|"bgm"=>"conflict","delete"|"delete_deck"|"delete_pending"=>"not_found",_=>"forbidden"});
                let outcome=repo.speech_request(&p.tenant_id,&r.id).await.unwrap().outcome;
                assert_eq!(outcome,match change{"edit"|"bgm"=>"conflict","delete"|"delete_deck"|"delete_pending"=>"not_found",_=>"requester_revoked"});
                if let Some(current)=repo.get_card(&p.tenant_id,&card.id).await.unwrap(){assert!(current.tts.is_none());}
            }
            let p=seed(repo).await;let deck=memoswish_protocol::examples::sample_deck();let mut card=memoswish_protocol::examples::sample_card();card.tts=None;repo.insert_deck_with_cards(&p.tenant_id,&deck,std::slice::from_ref(&card)).await.unwrap();
            let r=repo.accept_speech(&p,&work(),Some((&card.id,card.revision)),None).await.unwrap();materialize(repo,&p,&r).await;publish(repo,&p,&r).await;
            let first=repo.attach_speech(&p.tenant_id,&r.id).await.unwrap();assert_eq!(first.revision,card.revision+1);
            assert_eq!(repo.attach_speech(&p.tenant_id,&r.id).await.unwrap().revision,first.revision);
            let mut w=work();w.request.voice="second".into();let r=repo.accept_speech(&p,&w,Some((&card.id,first.revision)),None).await.unwrap();materialize(repo,&p,&r).await;publish(repo,&p,&r).await;
            sqlx::raw_sql(if $sqlite{"CREATE TRIGGER s16_ref_fail BEFORE INSERT ON asset_references WHEN NEW.slot='tts_card' BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;"}else{"CREATE FUNCTION s16_ref_fail_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.slot='tts_card' THEN RAISE EXCEPTION 'SECRET_SENTINEL'; END IF; RETURN NEW; END $$; CREATE TRIGGER s16_ref_fail BEFORE INSERT ON asset_references FOR EACH ROW EXECUTE FUNCTION s16_ref_fail_fn();"}).execute(repo.pool()).await.unwrap();
            assert!(repo.attach_speech(&p.tenant_id,&r.id).await.is_err());assert_eq!(repo.get_card(&p.tenant_id,&card.id).await.unwrap().unwrap(),first);assert_eq!(repo.speech_request(&p.tenant_id,&r.id).await.unwrap().outcome,"published");
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id=$1 AND owner_id=$2 AND slot='tts_card'").bind(&p.tenant_id).bind(&card.id).fetch_one(repo.pool()).await.unwrap();assert_eq!(count,1);
            sqlx::raw_sql(if $sqlite{"DROP TRIGGER s16_ref_fail;"}else{"DROP TRIGGER s16_ref_fail ON asset_references; DROP FUNCTION s16_ref_fail_fn();"}).execute(repo.pool()).await.unwrap();
            let second=repo.attach_speech(&p.tenant_id,&r.id).await.unwrap();assert_eq!(second.revision,first.revision+1);assert_eq!(second.tts.unwrap().voice,"second");
        }

        async fn session_requesters(repo: &$repo) {
            use memoswish_core::session::{SessionFamily, SessionCredential, SessionRepo};
            for phase in ["admission", "publication", "attachment"] {
                for change in ["rotate", "logout", "logout_all", "legacy_logout", "access_expiry", "family_expiry", "missing"] {
                    let p = seed(repo).await;
                    let now = chrono::Utc::now().timestamp();
                    let family = SessionFamily {id:memoswish_core::ids::new_id(), user_id:p.user_id.clone(), generation:0, provenance:"password".into(), auth_time:now-10, expires_at:now+3600, revoked:false};
                    let credential = SessionCredential {access_hash:memoswish_core::ids::new_id(), refresh_hash:memoswish_core::ids::new_id(), assurance_hash:memoswish_core::ids::new_id(), session_id:family.id.clone(), tenant_id:Some(p.tenant_id.clone()), membership_generation:Some(0), expires_at:now+600};
                    repo.session_issue(&family, &credential, None).await.unwrap();
                    let mut scoped = p.clone();
                    scoped.via = "session".into();
                    scoped.session_access_hash = Some(credential.access_hash.clone());
                    if change == "legacy_logout" {
                        scoped.via = "jwt".into();
                        scoped.session_access_hash = None;
                        scoped.legacy_issued_at = Some(family.auth_time);
                    }
                    let deck = memoswish_protocol::examples::sample_deck();
                    let mut card = memoswish_protocol::examples::sample_card();
                    card.tts = None;
                    repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
                    let target = Some((card.id.as_str(), card.revision));
                    let request = if phase == "admission" {None} else {Some(repo.accept_speech(&scoped, &work(), target, None).await.unwrap())};
                    if let Some(r) = &request {
                        materialize(repo, &p, r).await;
                        if phase == "attachment" {publish(repo, &p, r).await;}
                    }
                    let successor_hash = memoswish_core::ids::new_id();
                    match change {
                        "rotate" => {repo.session_rotate(&credential.refresh_hash, &successor_hash, &memoswish_core::ids::new_id(), &memoswish_core::ids::new_id(), 600).await.unwrap();},
                        "logout" => {assert!(repo.session_revoke(&credential.access_hash, &family.id).await.unwrap());},
                        "logout_all" | "legacy_logout" => {
                            let mut root_family = family.clone();
                            root_family.id = memoswish_core::ids::new_id();
                            let root = crate::session_conformance::credential(&root_family, None);
                            repo.session_issue(&root_family, &root, None).await.unwrap();
                            repo.session_revoke_all(&root.access_hash).await.unwrap();
                        },
                        "access_expiry" => {sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1").bind(&credential.access_hash).execute(repo.pool()).await.unwrap();},
                        "family_expiry" => {sqlx::query("UPDATE app_sessions SET expires_at=$2 WHERE id=$1").bind(&family.id).bind(now-1).execute(repo.pool()).await.unwrap();},
                        _ => {sqlx::query("DELETE FROM app_sessions WHERE id=$1").bind(&family.id).execute(repo.pool()).await.unwrap();},
                    }
                    if let Some(r) = &request {
                        if phase == "publication" {
                            // 同一合成的独立有效请求者继续发布，失效凭据不取得结果引用。
                            let peer = repo.accept_speech(&p, &work(), None, None).await.unwrap();
                            publish(repo, &p, r).await;
                            assert_eq!(repo.speech_request(&p.tenant_id, &peer.id).await.unwrap().outcome, "published");
                        }
                        assert!(matches!(repo.attach_speech(&p.tenant_id, &r.id).await, Err(CoreError::Forbidden(_))));
                        assert_eq!(repo.speech_request(&p.tenant_id, &r.id).await.unwrap().outcome, "requester_revoked");
                        assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
                        let slots:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id=$1 AND slot='tts_card'").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                        assert_eq!(slots, 0);
                    }
                    assert!(matches!(repo.accept_speech(&scoped, &work(), target, None).await, Err(CoreError::Forbidden(_))));
                    if change == "rotate" {
                        scoped.session_access_hash = Some(successor_hash);
                        let next = repo.accept_speech(&scoped, &work(), target, None).await.unwrap();
                        if let Some(r) = &request {
                            assert_ne!(r.id, next.id);
                            assert_eq!(r.synthesis_id, next.synthesis_id);
                            assert_eq!(next.outcome, "published");
                            assert!(repo.attach_speech(&p.tenant_id, &next.id).await.unwrap().tts.is_some());
                        }
                    }
                }
            }
            // 原凭据身份独立于双世代，换有效 access 后可共享结果但不能复用撤销回执。
            let p = seed(repo).await;
            let mut no_proof = p.clone(); no_proof.via = "session".into();
            assert!(matches!(repo.accept_speech(&no_proof, &work(), None, None).await, Err(CoreError::Forbidden(_))));
        }

        async fn exhausted_upload_requesters(repo: &$repo, p: &Principal) {
            let original = repo.accept_speech(p, &work(), None, Some(3)).await.unwrap();
            assert_eq!(original.outcome, "failed");
            let (upload, bytes) = repo.speech_upload(&p.tenant_id, &original.synthesis_id).await.unwrap().unwrap();
            assert_eq!(bytes, b"abc");
            let attempts = repo.upload_attempts(&p.tenant_id, &upload).await.unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].version, ObjectVersion::Unknown);
            let provider_attempts: Vec<(String, String)> = sqlx::query_as(
                "SELECT claim_token,outcome FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2 ORDER BY claim_token"
            ).bind(&p.tenant_id).bind(&original.synthesis_id).fetch_all(repo.pool()).await.unwrap();
            assert_eq!(provider_attempts.len(), 2);
            let period: String = sqlx::query_scalar(
                "SELECT period FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2"
            ).bind(&p.tenant_id).bind(&original.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3, 3));
            let mut member = seed(repo).await;
            repo.membership_join(&p.tenant_id, &member.user_id, Role::Editor).await.unwrap();
            member.tenant_id = p.tenant_id.clone();
            member.role = Role::Editor;
            let joined = repo.accept_speech(&member, &work(), None, Some(3)).await.unwrap();
            assert_ne!(joined.id, original.id);
            assert_eq!(joined.synthesis_id, original.synthesis_id);
            assert_eq!(joined.outcome, "failed");
            assert_eq!(repo.accept_speech(&member, &work(), None, Some(3)).await.unwrap(), joined);
            let mut deck = memoswish_protocol::examples::sample_deck();
            let mut card = memoswish_protocol::examples::sample_card();
            card.tts = None;
            // 同一成员的新卡片目标在耗尽后也必须立即获得终态。
            for _ in 0..2 {
                deck.id = memoswish_core::ids::new_id();
                card.deck_id = deck.id.clone();
                card.id = memoswish_core::ids::new_id();
                repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
                let target = Some((card.id.as_str(), card.revision));
                let joined = repo.accept_speech(p, &work(), target, Some(3)).await.unwrap();
                assert_ne!(joined.id, original.id);
                assert_eq!(joined.synthesis_id, original.synthesis_id);
                assert_eq!(joined.outcome, "failed");
                assert_eq!(repo.accept_speech(p, &work(), target, Some(3)).await.unwrap(), joined);
                assert_eq!(repo.speech_request(&p.tenant_id, &joined.id).await.unwrap(), joined);
                assert!(repo.attach_speech(&p.tenant_id, &joined.id).await.is_err());
                assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
                // 模拟修复前已持久化的悬挂请求，重放必须收敛且保留相同身份。
                sqlx::query("UPDATE tts_requesters SET outcome='pending' WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&joined.id).execute(repo.pool()).await.unwrap();
                assert_eq!(repo.accept_speech(p, &work(), target, Some(3)).await.unwrap(), joined);
            }
            // 重放与新准入不重启任一阶段，也不改变预留或外部尝试证据。
            assert!(repo.claim_speech(&p.tenant_id, &original.synthesis_id, 30_000).await.unwrap().is_none());
            assert!(repo.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().is_none());
            assert_eq!(repo.upload_attempts(&p.tenant_id, &upload).await.unwrap(), attempts);
            let after: Vec<(String, String)> = sqlx::query_as(
                "SELECT claim_token,outcome FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2 ORDER BY claim_token"
            ).bind(&p.tenant_id).bind(&original.synthesis_id).fetch_all(repo.pool()).await.unwrap();
            assert_eq!(after, provider_attempts);
            assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3, 3));
            assert_eq!(repo.get_usage(&p.tenant_id, "tts_chars", &period).await.unwrap(), 0);
            let reservations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM quota_operations WHERE tenant_id=$1")
                .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(reservations, 1);
            let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_requesters WHERE tenant_id=$1 AND outcome<>'failed'")
                .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(pending, 0);
        }

        async fn classified_failures_prepare(repo: &$repo) -> Vec<(Principal, SpeechRequest, SpeechFailure)> {
            let mut cases = Vec::new();
            for failure in [SpeechFailure::EngineUnavailable, SpeechFailure::VoiceUnavailable] {
                for expired in [false, true] {
                    let p = seed(repo).await;
                    let r = repo.accept_speech(&p, &work(), None, None).await.unwrap();
                    sqlx::query("UPDATE background_jobs SET max_attempts=$3 WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(&r.synthesis_id).bind(if expired { 2_i64 } else { 1_i64 }).execute(repo.pool()).await.unwrap();
                    let claim = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
                    repo.fail_speech(&p.tenant_id, &claim, Some(failure)).await.unwrap();
                    if expired {
                        sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&claim.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
                        repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
                        sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                            .bind(&p.tenant_id).bind(&r.synthesis_id).execute(repo.pool()).await.unwrap();
                    } else {
                        classified_failure_assert(repo, &p, &r, failure).await;
                    }
                    cases.push((p, r, failure));
                }
            }
            // 后续尝试进入 provider 后，旧的本地预检分类必须清除，uncertain 继续保留。
            let p = seed(repo).await;
            let r = repo.accept_speech(&p, &work(), None, None).await.unwrap();
            sqlx::query("UPDATE background_jobs SET max_attempts=2 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&r.synthesis_id).execute(repo.pool()).await.unwrap();
            let claim = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
            repo.fail_speech(&p.tenant_id, &claim, Some(SpeechFailure::VoiceUnavailable)).await.unwrap();
            sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&claim.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            let claim = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
            let code: Option<String> = sqlx::query_scalar("SELECT error FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&r.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(code, None);
            repo.fail_speech(&p.tenant_id, &claim, None).await.unwrap();
            let terminal = repo.speech_request(&p.tenant_id, &r.id).await.unwrap();
            assert_eq!(terminal.outcome, "failed");
            assert_eq!(terminal.failure, None);
            let period = chrono::Utc::now().format("%Y-%m").to_string();
            assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (3,3));
            // 隐私失效成为终态原因时也清除先前的本地诊断。
            let p = seed(repo).await;
            let r = repo.accept_speech(&p, &work(), None, None).await.unwrap();
            let claim = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
            repo.fail_speech(&p.tenant_id, &claim, Some(SpeechFailure::EngineUnavailable)).await.unwrap();
            assert!(repo.retire_invalid_speech(&p.tenant_id, &r.synthesis_id, &memoswish_protocol::examples::sample_privacy_policy(), true).await.unwrap());
            let terminal = repo.speech_request(&p.tenant_id, &r.id).await.unwrap();
            assert_eq!(terminal.outcome, "failed");
            assert_eq!(terminal.failure, None);
            assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (0,0));
            cases
        }

        async fn classified_failure_assert(repo: &$repo, p: &Principal, r: &SpeechRequest, failure: SpeechFailure) {
            assert!(repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().is_none());
            let terminal = repo.speech_request(&p.tenant_id, &r.id).await.unwrap();
            assert_eq!(terminal.outcome, "failed");
            assert_eq!(terminal.failure, Some(failure));
            assert_eq!(repo.accept_speech(p, &work(), None, None).await.unwrap(), terminal);
            let code: Option<String> = sqlx::query_scalar("SELECT error FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&r.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(code.as_deref(), Some(failure.error().code()));
            let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2")
                .bind(&p.tenant_id).bind(&r.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(attempts, 0);
            let period = chrono::Utc::now().format("%Y-%m").to_string();
            assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (0,0));
            assert_eq!(repo.get_usage(&p.tenant_id, "tts_chars", &period).await.unwrap(), 0);
        }

        async fn upload_exhaustion(repo: &$repo, other: &$repo) -> Vec<Principal> {
            let mut owners = Vec::new();
            for expired in [false, true] {
                let p = seed(repo).await;
                let request = repo.accept_speech(&p, &work(), None, Some(3)).await.unwrap();
                // 保留一个未知 provider 尝试，验证耗尽后的新请求不释放 uncertain。
                let lost = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
                repo.begin_provider(&p.tenant_id, &lost).await.unwrap();
                sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&request.synthesis_id).execute(repo.pool()).await.unwrap();
                materialize(other, &p, &request).await;
                let (upload, _) = repo.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().unwrap();
                sqlx::query("UPDATE background_jobs SET max_attempts=1 WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&upload).execute(repo.pool()).await.unwrap();
                let claim = repo.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().unwrap();
                repo.begin_upload(&p.tenant_id, &claim, "store").await.unwrap();
                if expired {
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(&upload).execute(repo.pool()).await.unwrap();
                    assert!(other.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().is_none());
                } else {
                    other.fail_speech(&p.tenant_id, &claim, None).await.unwrap();
                }
                let state: String = sqlx::query_scalar("SELECT state FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(state, "succeeded");
                let state: String = sqlx::query_scalar("SELECT state FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&upload).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(state, "dead");
                exhausted_upload_requesters(other, &p).await;
                // 旧版本悬挂请求跨关闭、重开后，首次重放也必须修正。
                sqlx::query("UPDATE tts_requesters SET outcome='pending' WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&request.id).execute(repo.pool()).await.unwrap();
                owners.push(p);
            }
            owners
        }

        async fn lifecycle_erasure(repo: &$repo, other: &$repo) {
            use crate::lifecycle_conformance::{account, confirmation, workspace};
            use memoswish_core::lifecycle::CloseAccount;
            for change in ["delete", "close", "legacy"] {
                for phase in ["queued", "claimed", "provider", "upload", "receipt", "published"] {
                    let p = workspace(repo).await;
                    let deck = memoswish_protocol::examples::sample_deck();
                    let mut card = memoswish_protocol::examples::sample_card();
                    card.tts = None;
                    repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
                    let r = repo.accept_speech(&p, &work(), Some((&card.id, card.revision)), None).await.unwrap();
                    let provider = if phase == "queued" { None } else {
                        Some(repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap())
                    };
                    if !matches!(phase, "queued" | "claimed") { repo.begin_provider(&p.tenant_id, provider.as_ref().unwrap()).await.unwrap(); }
                    let mut upload = None;
                    if matches!(phase, "upload" | "receipt" | "published") {
                        repo.materialize_speech(&p.tenant_id, provider.as_ref().unwrap(), b"abc", &spec(), &metadata(), false).await.unwrap();
                        let (id, _) = repo.speech_upload(&p.tenant_id, &r.synthesis_id).await.unwrap().unwrap();
                        let c = repo.claim_speech(&p.tenant_id, &id, 30_000).await.unwrap().unwrap();
                        let a = repo.begin_upload(&p.tenant_id, &c, "store").await.unwrap();
                        if phase != "upload" { repo.record_upload(&p.tenant_id, &a, &ObjectVersion::VersionId("exact".into())).await.unwrap(); }
                        if phase == "published" { repo.publish_speech(&p.tenant_id, &c, &a.id).await.unwrap(); }
                        upload = Some((c, a));
                    }
                    let period: String = sqlx::query_scalar("SELECT period FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2")
                        .bind(&p.tenant_id).bind(&r.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                    match change {
                        "delete" => { other.delete_workspace(&p, &confirmation(&p)).await.unwrap(); },
                        "close" => { other.close_account(&account(&p), &CloseAccount { confirmed_exclusive_workspaces: vec![p.tenant_id.clone()] }).await.unwrap(); },
                        _ => { other.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap(); },
                    }
                    assert_eq!(repo.speech_request(&p.tenant_id, &r.id).await.unwrap().outcome, "requester_revoked");
                    assert!(matches!(repo.attach_speech(&p.tenant_id, &r.id).await, Err(CoreError::Forbidden(_))));
                    assert!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().is_none());
                    assert!(repo.accept_speech(&p, &work(), None, None).await.is_err());
                    assert!(repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().is_none());
                    if let Some(c) = &provider {
                        assert!(repo.begin_provider(&p.tenant_id, c).await.is_err());
                        assert!(repo.materialize_speech(&p.tenant_id, c, b"abc", &spec(), &metadata(), false).await.is_err());
                        assert!(repo.fail_speech(&p.tenant_id, c, None).await.is_err());
                    }
                    if let Some((c, a)) = &upload {
                        // 晚到精确回执继续入账供清理，但旧 claim 不能产生挂载或费用。
                        repo.record_upload(&p.tenant_id, a, &ObjectVersion::VersionId("exact".into())).await.unwrap();
                        assert!(repo.publish_speech(&p.tenant_id, c, &a.id).await.is_err());
                        assert!(repo.begin_upload(&p.tenant_id, c, "store").await.is_err());
                        assert!(repo.claim_speech(&p.tenant_id, &c.job_id, 30_000).await.unwrap().is_none());
                        assert_eq!(repo.upload_attempts(&p.tenant_id, &c.job_id).await.unwrap()[0].version, ObjectVersion::VersionId("exact".into()));
                    }
                    let state: String = sqlx::query_scalar("SELECT state FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2")
                        .bind(&p.tenant_id).bind(&r.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(state, match phase { "queued" | "claimed" => "released", "published" => "committed", _ => "reserved" });
                    let expected = match phase { "queued" | "claimed" | "published" => (0, 0), "provider" => (3, 3), _ => (3, 0) };
                    assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), expected);
                    assert_eq!(repo.get_usage(&p.tenant_id, "tts_chars", &period).await.unwrap(), 0);
                    assert!(!repo.pending_speech(None, 100).await.unwrap().iter().any(|(t, _)| t == &p.tenant_id));
                    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND kind IN ('tts_synthesis','asset_upload') AND (state<>'dead' OR token IS NOT NULL OR lease_until_ms<>0)")
                        .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(active, 0);
                    let recovery:i64=sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND kind='erasure' AND state='queued'").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(recovery,1);
                    let private:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tts_syntheses WHERE tenant_id=$1 AND (audio IS NOT NULL OR metadata IS NOT NULL OR work<>'{}')").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(private,0);
                    let refs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id=$1")
                        .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(refs, 0);
                }
            }
        }

        async fn regressions(repo:&$repo,other:&$repo){
            s17_faults(repo).await;
            s17_credentials(repo).await;
            s17_app_session_fences(repo).await;
            submissions::submissions(repo,other).await;
            submissions::deletion_and_atomic_validation(repo).await;
            lifecycle_requesters(repo).await;
            s6_receipt_lifecycle(repo).await;
            lifecycle_erasure(repo, other).await;
            attachments(repo).await;
            sharing(repo,other).await;
            session_requesters(repo).await;
            let p=seed(repo).await;let r=repo.accept_speech(&p,&work(),None,None).await.unwrap();
            let c=repo.claim_speech(&p.tenant_id,&r.synthesis_id,30_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id,&c).await.unwrap();
            // 锁后数据库时钟和旧 token fence，过期 A 不能交接 B 的输出。
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&c.job_id).execute(repo.pool()).await.unwrap();
            let b=other.claim_speech(&p.tenant_id,&r.synthesis_id,30_000).await.unwrap().unwrap();
            assert!(repo.materialize_speech(&p.tenant_id,&c,b"abc",&spec(),&metadata(),false).await.is_err());
            assert!(repo.fail_speech(&p.tenant_id,&c,None).await.is_err());
            other.begin_provider(&p.tenant_id,&b).await.unwrap();
            other.materialize_speech(&p.tenant_id,&b,b"abc",&spec(),&metadata(),false).await.unwrap();
            let (upload,_)=repo.speech_upload(&p.tenant_id,&r.synthesis_id).await.unwrap().unwrap();
            let old=repo.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().unwrap();
            let late=repo.begin_upload(&p.tenant_id,&old,"store").await.unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&upload).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE background_jobs SET max_attempts=2 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&upload).execute(repo.pool()).await.unwrap();
            let fresh=other.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().unwrap();
            let win=other.begin_upload(&p.tenant_id,&fresh,"store").await.unwrap();
            assert_ne!(late.key,win.key);
            other.record_upload(&p.tenant_id,&win,&ObjectVersion::VersionId("winner".into())).await.unwrap();
            // 结算必须使用原始月份，而非恢复月份。
            sqlx::query("UPDATE quota_operations SET period='2001-01' WHERE tenant_id=$1 AND operation_id=$2").bind(&p.tenant_id).bind(&r.synthesis_id).execute(repo.pool()).await.unwrap();
            other.publish_speech(&p.tenant_id,&fresh,&win.id).await.unwrap();
            repo.record_upload(&p.tenant_id,&late,&ObjectVersion::VersionId("late".into())).await.unwrap();
            assert!(repo.publish_speech(&p.tenant_id,&old,&late.id).await.is_err());
            assert_eq!(repo.get_usage(&p.tenant_id,"tts_chars","2001-01").await.unwrap(),3);
            assert_eq!(repo.upload_attempts(&p.tenant_id,&upload).await.unwrap().len(),2);
            assert!(repo.unresolved_assets(None,100).await.unwrap().iter().any(|(t,i)|t==&p.tenant_id&&i.id==upload));
            // 已发布结果优先于遗留 attempt 清理的 dead 状态，新成员仍取得发布结果。
            let state: String = sqlx::query_scalar("SELECT state FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&upload).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(state, "dead");
            let mut member = seed(repo).await;
            repo.membership_join(&p.tenant_id, &member.user_id, Role::Editor).await.unwrap();
            member.tenant_id = p.tenant_id.clone();
            member.role = Role::Editor;
            assert_eq!(repo.accept_speech(&member, &work(), None, Some(3)).await.unwrap().outcome, "published");
            // exhausted provider uncertainty remains held and discoverable, across requester removal.
            let p=seed(repo).await;let r=repo.accept_speech(&p,&work(),None,None).await.unwrap();
            sqlx::query("UPDATE background_jobs SET max_attempts=1 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&r.synthesis_id).execute(repo.pool()).await.unwrap();
            let c=repo.claim_speech(&p.tenant_id,&r.synthesis_id,30_000).await.unwrap().unwrap();repo.begin_provider(&p.tenant_id,&c).await.unwrap();repo.fail_speech(&p.tenant_id,&c,None).await.unwrap();
            let period=chrono::Utc::now().format("%Y-%m").to_string();assert_eq!(repo.held_speech_usage(&p.tenant_id,&period).await.unwrap(),(3,3));
            assert_eq!(repo.speech_request(&p.tenant_id,&r.id).await.unwrap().outcome,"failed");
            assert!(repo.pending_speech(None,100).await.unwrap().iter().any(|(t,i)|t==&p.tenant_id&&i==&r.synthesis_id));
            // 上传接管耗尽也必须给请求者终态，同时保留未知 PUT 和 held。
            let p=seed(repo).await;let r=repo.accept_speech(&p,&work(),None,None).await.unwrap();materialize(repo,&p,&r).await;
            let (upload,_)=repo.speech_upload(&p.tenant_id,&r.synthesis_id).await.unwrap().unwrap();
            sqlx::query("UPDATE background_jobs SET max_attempts=1 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&upload).execute(repo.pool()).await.unwrap();
            let c=repo.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().unwrap();let a=repo.begin_upload(&p.tenant_id,&c,"store").await.unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&upload).execute(repo.pool()).await.unwrap();
            assert!(repo.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().is_none());assert_eq!(repo.speech_request(&p.tenant_id,&r.id).await.unwrap().outcome,"failed");
            assert_eq!(repo.upload_attempts(&p.tenant_id,&upload).await.unwrap()[0].id,a.id);assert_eq!(repo.upload_attempts(&p.tenant_id,&upload).await.unwrap()[0].outcome,UploadOutcome::Uncertain);assert_eq!(repo.held_speech_usage(&p.tenant_id,&period).await.unwrap(),(3,0));
            // 没有 provider 调用证据的终态才可以释放。
            let p=seed(repo).await;let r=repo.accept_speech(&p,&work(),None,None).await.unwrap();sqlx::query("UPDATE background_jobs SET max_attempts=1 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&r.synthesis_id).execute(repo.pool()).await.unwrap();let c=repo.claim_speech(&p.tenant_id,&r.synthesis_id,30_000).await.unwrap().unwrap();repo.fail_speech(&p.tenant_id,&c,None).await.unwrap();assert_eq!(repo.held_speech_usage(&p.tenant_id,&period).await.unwrap(),(0,0));
            // 数据库错误不得泄漏注入原文，发布/账本/引用必须整体回滚。
            let p=seed(repo).await;let r=repo.accept_speech(&p,&work(),None,None).await.unwrap();materialize(repo,&p,&r).await;
            let (upload,_)=repo.speech_upload(&p.tenant_id,&r.synthesis_id).await.unwrap().unwrap();let c=repo.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().unwrap();let a=repo.begin_upload(&p.tenant_id,&c,"store").await.unwrap();repo.record_upload(&p.tenant_id,&a,&ObjectVersion::Unversioned).await.unwrap();
            let trigger=if $sqlite {"CREATE TRIGGER s16_fail BEFORE INSERT ON usage_counters BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;"}else{"CREATE FUNCTION s16_fail_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SECRET_SENTINEL'; END $$; CREATE TRIGGER s16_fail BEFORE INSERT ON usage_counters FOR EACH ROW EXECUTE FUNCTION s16_fail_fn();"};
            sqlx::raw_sql(trigger).execute(repo.pool()).await.unwrap();
            let e=repo.publish_speech(&p.tenant_id,&c,&a.id).await.unwrap_err();assert!(!format!("{e:?} {e}").contains("SECRET_SENTINEL"));
            assert!(repo.asset_intent(&p.tenant_id,&upload).await.unwrap().unwrap().published_attempt.is_none());
            assert_eq!(repo.get_usage(&p.tenant_id,"tts_chars",&period).await.unwrap(),0);
            sqlx::raw_sql(if $sqlite{"DROP TRIGGER s16_fail;"}else{"DROP TRIGGER s16_fail ON usage_counters; DROP FUNCTION s16_fail_fn();"}).execute(repo.pool()).await.unwrap();
            // SQL 提交后丢响应由读取证明；重放不结算第二次。
            repo.publish_speech(&p.tenant_id,&c,&a.id).await.unwrap();assert!(repo.publish_speech(&p.tenant_id,&c,&a.id).await.is_err());assert!(repo.speech_track(&p.tenant_id,&r.synthesis_id).await.unwrap().is_some());assert_eq!(repo.get_usage(&p.tenant_id,"tts_chars",&period).await.unwrap(),3);
            // 撤销第一个请求者仍发布共享资产，但只给仍有效的请求者结果引用。
            let p=seed(repo).await;let mut peer=seed(repo).await;repo.membership_join(&p.tenant_id,&peer.user_id,Role::Editor).await.unwrap();peer.tenant_id=p.tenant_id.clone();peer.role=Role::Editor;
            let r=repo.accept_speech(&p,&work(),None,None).await.unwrap();let m=repo.accept_speech(&peer,&work(),None,None).await.unwrap();materialize(repo,&p,&r).await;repo.membership_remove(&p.tenant_id,&p.user_id).await.unwrap();publish(repo,&p,&r).await;
            assert_eq!(repo.speech_request(&p.tenant_id,&r.id).await.unwrap().outcome,"requester_revoked");assert_eq!(repo.speech_request(&p.tenant_id,&m.id).await.unwrap().outcome,"published");
        }
    }
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    suite!(SqliteRepository, sqlx::SqlitePool, true, "./migrations/sqlite");
    #[tokio::test]
    async fn sqlite_submission_upgrade_rollback_and_preservation() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        s17_upgrade(&pool).await;
        pool.close().await;
    }
    #[tokio::test]
    async fn sqlite_speech_upgrade_rollback_and_preservation() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
    }
    #[tokio::test]
    async fn sqlite_speech_conformance_and_restart() {
        let path = std::env::temp_dir().join(format!("s16-{}.sqlite", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let other = SqliteRepository::connect_test(&url).await.unwrap();
        regressions(&repo, &other).await;
        let s17_restart = submissions::restart_prepare(&repo).await;
        let exhausted = upload_exhaustion(&repo, &other).await;
        let classified = classified_failures_prepare(&repo).await;
        let p = seed(&repo).await;
        let r = repo.accept_speech(&p, &work(), None, None).await.unwrap();
        repo.pool().close().await;
        other.pool().close().await;
        let reopened = SqliteRepository::connect_test(&url).await.unwrap();
        for (p, r, failure) in classified {
            classified_failure_assert(&reopened, &p, &r, failure).await;
        }
        submissions::restart_finish(&reopened, s17_restart).await;
        for owner in exhausted {
            exhausted_upload_requesters(&reopened, &owner).await;
        }
        assert_eq!(reopened.speech_request(&p.tenant_id, &r.id).await.unwrap(), r);
        assert!(reopened.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().is_some());
        reopened.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    suite!(PostgresRepository, sqlx::PgPool, false, "./migrations/postgres");
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_submission_upgrade_rollback_and_preservation() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            s17_upgrade(&pool).await;
            pool.close().await;
            fixture.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_speech_upgrade_rollback_and_preservation() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            upgrade(&pool).await;
            pool.close().await;
            fixture.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_speech_conformance_and_restart() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let repo = fixture.repository(8).await.unwrap();
            let other = fixture.repository(8).await.unwrap();
            regressions(&repo, &other).await;
            let s17_restart = submissions::restart_prepare(&repo).await;
            let exhausted = upload_exhaustion(&repo, &other).await;
            let classified = classified_failures_prepare(&repo).await;
            let p = seed(&repo).await;
            let r = repo.accept_speech(&p, &work(), None, None).await.unwrap();
            materialize(&repo, &p, &r).await;
            repo.pool().close().await;
            other.pool().close().await;
            let reopened = fixture.repository(8).await.unwrap();
            for (p, r, failure) in classified {
                classified_failure_assert(&reopened, &p, &r, failure).await;
            }
            submissions::restart_finish(&reopened, s17_restart).await;
            for owner in exhausted {
                exhausted_upload_requesters(&reopened, &owner).await;
            }
            assert_eq!(reopened.speech_request(&p.tenant_id, &r.id).await.unwrap(), r);
            assert!(reopened.speech_upload(&p.tenant_id, &r.synthesis_id).await.unwrap().is_some());
            reopened.pool().close().await;
            fixture.cleanup().await;
        });
    }
}
