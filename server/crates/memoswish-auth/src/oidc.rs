//! OIDC 登录识别本地用户，与 MCP 授权同意和令牌发行独立。
mod network;
mod verification;
pub use crate::flow::{challenge, digest, equal, now, secret};
use crate::{AuthService, RateLimiter, oidc_config::*};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, jwk::JwkSet};
use memoswish_core::{CoreError, CoreResult, CredentialGenerations, Principal, Role, identity::*, repo::*};
use memoswish_protocol::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

fn denied() -> CoreError {
    CoreError::Unauthorized("invalid OIDC transaction or token".into())
}
fn sanitized_name(s: &str) -> Option<String> {
    let name = s.chars().filter(|c| !c.is_control()).take(128).collect::<String>();
    let name = name.trim();
    if name.is_empty() { None } else { Some(name.into()) }
}

#[derive(Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}
#[derive(Default)]
struct Cache {
    discovery: Option<Discovery>,
    discovery_until: i64,
    keys: Option<JwkSet>,
    keys_until: i64,
    rotation_at: i64,
    discovery_retry: i64,
    keys_retry: i64,
}

#[derive(Clone)]
pub struct OidcService {
    pub config: OidcConfig,
    pub repo: Arc<dyn Repository>,
    auth: AuthService,
    key: crate::keys::EnvelopeKeys,
    caches: Arc<HashMap<String, Mutex<Cache>>>,
    limiter: Arc<dyn memoswish_core::rate_limit::RateLimiter>,
    default_plan: String,
}

impl OidcService {
    pub async fn linked_identities(&self, jwt: &str) -> CoreResult<Vec<LinkedIdentity>> {
        let p = self.auth.authenticate(Some(jwt)).await?;
        if !["jwt", "session"].contains(&p.via.as_str()) || p.scopes.is_some() {
            return Err(CoreError::Forbidden("identity management requires an unrestricted app session".into()));
        }
        Ok(self
            .repo
            .identity_list(&p.tenant_id, &p.user_id)
            .await?
            .into_iter()
            .map(|i| LinkedIdentity { provider: i.provider, issuer: i.issuer, subject: i.subject, email: i.email })
            .collect())
    }

    pub async fn unlink_identity(&self, provider: &str, jwt: &str) -> CoreResult<bool> {
        let p = self.auth.authenticate(Some(jwt)).await?;
        if !["jwt", "session"].contains(&p.via.as_str()) || p.scopes.is_some() {
            return Err(CoreError::Forbidden("identity management requires an unrestricted app session".into()));
        }
        let clients = self
            .config
            .providers
            .iter()
            .map(|p| {
                let mut clients = p.native_client_ids.clone();
                clients.push(p.client_id.clone());
                (p.id.clone(), p.issuer.clone(), clients)
            })
            .collect::<Vec<_>>();
        self.repo
            .identity_unlink(
                &p.tenant_id,
                &p.user_id,
                CredentialGenerations {
                    account: p.auth_generation.ok_or_else(denied)?,
                    membership: p.membership_generation.ok_or_else(denied)?,
                },
                provider,
                &memoswish_core::ids::sha256_hex(jwt.as_bytes()),
                now(),
                &clients,
            )
            .await
    }
    pub fn new(
        config: OidcConfig,
        repo: Arc<dyn Repository>,
        auth: AuthService,
        default_plan: String,
    ) -> CoreResult<Self> {
        config.validate()?;
        for provider in &config.providers {
            if provider.kind == "apple" {
                apple_client_secret(provider, now())?;
            }
        }
        let active = if config.encryption_key_id.is_empty() { "legacy" } else { &config.encryption_key_id };
        let mut keys = config.encryption_keys.clone();
        if keys.is_empty() {
            keys.insert(
                active.into(),
                crate::token::VerificationKey { secret: config.encryption_key.clone(), verify_until: None },
            );
        }
        let key = crate::keys::EnvelopeKeys::new(
            active,
            &keys,
            if config.encryption_key.is_empty() { None } else { Some(config.encryption_key.as_str()) },
            config.legacy_encryption_until,
        )?;
        let caches = config.providers.iter().map(|p| (p.id.clone(), Mutex::new(Cache::default()))).collect();
        Ok(Self {
            config,
            repo,
            auth,
            key,
            caches: Arc::new(caches),
            limiter: Arc::new(RateLimiter::new(60, 1.0)),
            default_plan,
        })
    }
    pub async fn reencrypt(&self) -> CoreResult<u64> {
        let service = self.clone();
        self.repo.identity_reencrypt(&move |text, context| service.rekey(text, context)).await
    }
    fn rekey(&self, text: &str, context: &str) -> CoreResult<String> {
        let mut plain = self.key.open(text, context)?;
        if context == "pending-link" {
            let (identity, credential): (FederatedIdentity, Option<String>) =
                serde_json::from_str(&plain).map_err(|_| denied())?;
            let credential = credential
                .map(|v| {
                    let (aad, cipher) = v.split_once('\n').ok_or_else(denied)?;
                    Ok::<_, CoreError>(format!("{aad}\n{}", self.rekey(cipher, aad)?))
                })
                .transpose()?;
            let new = serde_json::to_string(&(identity, credential)).map_err(CoreError::internal)?;
            if self.key.is_active(text) && new == plain {
                return Ok(text.into());
            }
            plain = new;
        } else if self.key.is_active(text) {
            return Ok(text.into());
        }
        self.key.seal(&plain, context)
    }
    pub async fn limited(&self, bucket: &str) -> CoreResult<()> {
        self.limiter.check(bucket, 1.0).await
    }
    pub fn with_limiter(mut self, limiter: Arc<dyn memoswish_core::rate_limit::RateLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    fn provider(&self, id: &str) -> CoreResult<&OidcProvider> {
        self.config.providers.iter().find(|p| p.id == id).ok_or_else(|| CoreError::NotFound("OIDC provider".into()))
    }
    fn seal(&self, plaintext: &str, aad: &str) -> CoreResult<String> {
        self.key.seal(plaintext, aad)
    }
    fn open(&self, ciphertext: &str, aad: &str) -> CoreResult<String> {
        self.key.open(ciphertext, aad)
    }
    async fn discovery(&self, p: &OidcProvider) -> CoreResult<Discovery> {
        let mut c = self.caches[&p.id].lock().await;
        if c.discovery_until > now()
            && let Some(d) = &c.discovery
        {
            return Ok(d.clone());
        }
        if c.discovery_retry > now() {
            return Err(CoreError::internal("OIDC discovery temporarily unavailable"));
        }
        c.discovery_retry = now() + 5;
        let client = network::client(p, &p.discovery_url).await?;
        let (d, ttl): (Discovery, _) = network::json(
            client
                .get(&p.discovery_url)
                .send()
                .await
                .map_err(|_| CoreError::internal("OIDC discovery request failed"))?,
        )
        .await?;
        if d.issuer != p.issuer
            || !d.id_token_signing_alg_values_supported.iter().any(|a| p.algorithms.contains(a))
            || p.kind != "apple" && !d.code_challenge_methods_supported.iter().any(|a| a == "S256")
        {
            return Err(CoreError::invalid("OIDC discovery profile mismatch"));
        }
        if !d.token_endpoint_auth_methods_supported.is_empty()
            && !d.token_endpoint_auth_methods_supported.contains(&p.token_auth_method)
        {
            return Err(CoreError::invalid("OIDC token authentication method is not supported"));
        }
        for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri] {
            p.validate_url(u)?;
        }
        if let Some(u) = &d.revocation_endpoint {
            p.validate_url(u)?;
        }
        if p.kind == "apple" && d.revocation_endpoint.is_none() {
            return Err(CoreError::invalid("Apple revocation endpoint is required"));
        }
        c.discovery_retry = 0;
        c.discovery = Some(d.clone());
        c.discovery_until = now() + ttl as i64;
        Ok(d)
    }
    async fn keys(&self, p: &OidcProvider, d: &Discovery, rotate: bool) -> CoreResult<(JwkSet, bool)> {
        let mut c = self.caches[&p.id].lock().await;
        if rotate && now() - c.rotation_at < 30 {
            return if c.keys_until > now() { Ok((c.keys.clone().ok_or_else(denied)?, false)) } else { Err(denied()) };
        }
        if !rotate && c.keys.is_some() && c.keys_until > now() {
            return Ok((c.keys.clone().unwrap(), false));
        }
        // 失败也进入冷却，避免未知 kid 或上游故障形成请求放大。
        if rotate {
            c.rotation_at = now();
        }
        if c.keys_retry > now() {
            return Err(CoreError::internal("OIDC JWKS temporarily unavailable"));
        }
        c.keys_retry = now() + 5;
        let client = network::client(p, &d.jwks_uri).await?;
        let (keys, ttl): (JwkSet, _) = network::json(
            client.get(&d.jwks_uri).send().await.map_err(|_| CoreError::internal("OIDC JWKS request failed"))?,
        )
        .await?;
        if keys.keys.is_empty() || keys.keys.len() > 32 {
            return Err(CoreError::invalid("OIDC JWKS key count exceeds bounds"));
        }
        c.keys_retry = 0;
        c.keys = Some(keys.clone());
        c.keys_until = now() + ttl as i64;
        Ok((keys, true))
    }
    pub async fn validate_id_token(
        &self,
        id: &str,
        token: &str,
        nonce: &str,
        client_id: &str,
    ) -> CoreResult<serde_json::Value> {
        self.validate_jwt_profile(id, token, nonce, client_id, false).await
    }
    async fn validate_jwt_profile(
        &self,
        id: &str,
        token: &str,
        nonce: &str,
        client_id: &str,
        events: bool,
    ) -> CoreResult<serde_json::Value> {
        if token.len() > 16 * 1024 {
            return Err(denied());
        }
        let p = self.provider(id)?;
        if client_id != p.client_id && !p.native_client_ids.iter().any(|c| c == client_id) {
            return Err(denied());
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| denied())?;
        if !p.algorithms.iter().any(|a| a == &format!("{:?}", header.alg))
            || !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256)
            || header.crit.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(denied());
        }
        let kid = header.kid.as_deref().filter(|k| !k.is_empty() && k.len() <= 256).ok_or_else(denied)?;
        let d = self.discovery(p).await?;
        if !d.id_token_signing_alg_values_supported.iter().any(|a| a == &format!("{:?}", header.alg)) {
            return Err(denied());
        }
        let mut claims = None;
        let mut fetched = false;
        for rotate in [false, true] {
            if rotate && fetched {
                break;
            }
            let (keys, did_fetch) = self.keys(p, &d, rotate).await?;
            fetched |= did_fetch;
            let candidates = keys.keys.iter().filter(|k| k.common.key_id.as_deref() == Some(kid)).collect::<Vec<_>>();
            if candidates.len() > 1 {
                return Err(denied());
            }
            if let Some(k) = candidates.first() {
                use jsonwebtoken::jwk::{AlgorithmParameters, KeyOperations, PublicKeyUse};
                let compatible = matches!(
                    (&k.algorithm, header.alg),
                    (AlgorithmParameters::RSA(_), Algorithm::RS256)
                        | (AlgorithmParameters::EllipticCurve(_), Algorithm::ES256)
                );
                if !compatible
                    || k.common.public_key_use.as_ref().is_some_and(|u| *u != PublicKeyUse::Signature)
                    || k.common.key_operations.as_ref().is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
                    || k.common.key_algorithm.as_ref().is_some_and(|a| a.to_string() != format!("{:?}", header.alg))
                {
                    return Err(denied());
                }
                match &k.algorithm {
                    AlgorithmParameters::RSA(rsa) => {
                        let modulus = URL_SAFE_NO_PAD.decode(&rsa.n).map_err(|_| denied())?;
                        let exponent = URL_SAFE_NO_PAD.decode(&rsa.e).map_err(|_| denied())?;
                        if !(256..=1024).contains(&modulus.len()) || exponent.is_empty() || exponent.len() > 8 {
                            return Err(denied());
                        }
                    }
                    AlgorithmParameters::EllipticCurve(ec) => {
                        if ec.curve != jsonwebtoken::jwk::EllipticCurve::P256 {
                            return Err(denied());
                        }
                    }
                    _ => return Err(denied()),
                }
                if !events {
                    match verification::verify(p, client_id, token, nonce, k, header.alg) {
                        Ok(c) => {
                            claims = Some(c);
                            break;
                        }
                        Err(true) => continue,
                        Err(false) => return Err(denied()),
                    }
                }
                let key = DecodingKey::from_jwk(k).map_err(|_| denied())?;
                let mut validation = Validation::new(header.alg);
                validation.set_issuer(&[&p.issuer]);
                validation.set_audience(&[client_id]);
                validation.leeway = 30;
                validation.validate_nbf = true;
                validation.validate_exp = !events;
                if events {
                    validation.set_required_spec_claims(&["iss", "aud"]);
                } else {
                    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
                }
                match jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation) {
                    Ok(data) => {
                        claims = Some(data.claims);
                        break;
                    }
                    Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature) => continue,
                    Err(_) => return Err(denied()),
                }
            }
        }
        let c = claims.ok_or_else(denied)?;
        if c["iss"].as_str() != Some(p.issuer.as_str()) {
            return Err(denied());
        }
        if c.get("nbf").is_some_and(|v| v.as_i64().is_none_or(|n| n > now() + 30)) {
            return Err(denied());
        }
        let iat = c["iat"].as_i64().ok_or_else(denied)?;
        if iat > now() + 30 || iat < now() - 86400 {
            return Err(denied());
        }
        if !events {
            let exp = c["exp"].as_i64().ok_or_else(denied)?;
            if exp <= iat
                || exp < now() - 30
                || c["sub"].as_str().is_none_or(|s| s.is_empty() || s.len() > 255)
                || !c["nonce"].as_str().is_some_and(|n| equal(n, nonce))
            {
                return Err(denied());
            }
        }
        let audiences = match &c["aud"] {
            serde_json::Value::String(s) => vec![s.as_str()],
            serde_json::Value::Array(v) => {
                v.iter().map(|s| s.as_str().ok_or_else(denied)).collect::<CoreResult<Vec<_>>>()?
            }
            _ => return Err(denied()),
        };
        if audiences.is_empty()
            || audiences.iter().any(|a| *a != p.client_id && !p.native_client_ids.iter().any(|n| n == a))
            || (audiences.len() > 1 && c["azp"].as_str() != Some(client_id))
            || (c.get("azp").is_some() && c["azp"].as_str() != Some(client_id))
        {
            return Err(denied());
        }
        Ok(c)
    }
    /// Apple 通知不是 ID-token：没有 nonce/exp/sub，使用独立的严格事件配置。
    pub async fn apple_event(&self, id: &str, payload: &str) -> CoreResult<()> {
        self.limited("apple-event").await?;
        let p = self.provider(id)?;
        if p.kind != "apple" || payload.len() > 16 * 1024 {
            return Err(denied());
        }
        let untrusted = payload.split('.').nth(1).ok_or_else(denied)?;
        let bytes = URL_SAFE_NO_PAD.decode(untrusted).map_err(|_| denied())?;
        let hints: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| denied())?;
        // 未验证 audience 仅选择固定配置，所有实际动作均在签名验证之后。
        let audience = hints["aud"].as_str().ok_or_else(denied)?;
        let c = self.validate_jwt_profile(id, payload, "", audience, true).await?;
        let event = if let Some(s) = c["events"].as_str() {
            serde_json::from_str(s).map_err(|_| denied())?
        } else {
            c["events"].clone()
        };
        let subject = event["sub"].as_str().filter(|s| !s.is_empty() && s.len() <= 255).ok_or_else(denied)?;
        let kind = event["type"]
            .as_str()
            .filter(|s| ["email-enabled", "email-disabled", "consent-revoked", "account-deleted"].contains(s))
            .ok_or_else(denied)?;
        let at = event["event_time"].as_i64().filter(|t| *t <= now() + 30 && *t >= now() - 86400).ok_or_else(denied)?;
        let jti = c["jti"].as_str().filter(|s| !s.is_empty() && s.len() <= 256).ok_or_else(denied)?;
        self.repo.identity_event(&p.issuer, subject, &digest(jti), kind, at, now()).await
    }
    pub fn callback_url(&self, id: &str) -> String {
        format!("{}/v1/auth/oidc/{id}/callback", self.config.public_base_url.trim_end_matches('/'))
    }
    pub async fn link_start(&self, id: &str, r: &OidcStartRequest, jwt: &str) -> CoreResult<OidcStartResponse> {
        let principal = self.auth.authenticate(Some(jwt)).await?;
        self.start(id, r, Some((&principal, jwt))).await
    }
    pub async fn start(
        &self,
        id: &str,
        r: &OidcStartRequest,
        link: Option<(&Principal, &str)>,
    ) -> CoreResult<OidcStartResponse> {
        self.limited("start").await?;
        if let Some((principal, _)) = link {
            self.auth.require_privacy_collection(principal).await?;
        }
        let p = self.provider(id)?;
        if !self.config.return_uris.contains(&r.return_uri)
            || r.app_state.is_empty()
            || r.app_state.len() > 256
            || URL_SAFE_NO_PAD.decode(&r.code_challenge).map_or(true, |v| v.len() != 32)
        {
            return Err(CoreError::invalid("invalid OIDC return URI, app state or S256 challenge"));
        }
        if let Some((principal, jwt)) = link
            && (!["jwt", "session"].contains(&principal.via.as_str())
                || principal.scopes.is_some()
                || !self
                    .repo
                    .identity_check_recent(
                        &principal.tenant_id,
                        &principal.user_id,
                        CredentialGenerations {
                            account: principal.auth_generation.ok_or_else(denied)?,
                            membership: principal.membership_generation.ok_or_else(denied)?,
                        },
                        &memoswish_core::ids::sha256_hex(jwt.as_bytes()),
                        now(),
                    )
                    .await?)
        {
            return Err(CoreError::Forbidden("identity linking requires interactive login within five minutes".into()));
        }
        let deadline = if let Some((p, jwt)) = link {
            self.repo
                .identity_recent_deadline(
                    &p.tenant_id,
                    &p.user_id,
                    CredentialGenerations {
                        account: p.auth_generation.ok_or_else(denied)?,
                        membership: p.membership_generation.ok_or_else(denied)?,
                    },
                    &memoswish_core::ids::sha256_hex(jwt.as_bytes()),
                )
                .await?
                .ok_or_else(denied)?
                .min(now() + 300)
        } else {
            now() + 300
        };
        let native = r.native_client_id.is_some();
        let client_id = if let Some(n) = &r.native_client_id {
            if !p.native_client_ids.contains(n) {
                return Err(CoreError::invalid("unconfigured native client"));
            }
            n.clone()
        } else {
            p.client_id.clone()
        };
        let attempt_id = secret("")?;
        let state = secret("")?;
        let launch = secret("")?;
        let nonce = secret("")?;
        let a = LoginAttempt {
            link_legacy_issued_at: link.filter(|(p, _)| p.via == "jwt").and_then(|(p, _)| p.legacy_issued_at),
            link_access_hash: link
                .filter(|(p, _)| p.via == "session")
                .map(|(_, t)| crate::sessions::access_hash(t))
                .transpose()?,
            id: attempt_id.clone(),
            provider: id.into(),
            state_hash: digest(&state),
            launch_hash: if native { challenge(&r.code_challenge) } else { digest(&launch) },
            browser_hash: String::new(),
            nonce: nonce.clone(),
            verifier_ciphertext: self.seal(&secret("")?, &attempt_id)?,
            client_id,
            return_uri: r.return_uri.clone(),
            app_state: r.app_state.clone(),
            challenge: r.code_challenge.clone(),
            native,
            link_tenant: link.map(|(p, _)| p.tenant_id.clone()),
            link_user: link.map(|(p, _)| p.user_id.clone()),
            link_generation: link.and_then(|(p, _)| p.auth_generation),
            link_membership_generation: link.and_then(|(p, _)| p.membership_generation),
            link_session_hash: link.map(|(_, jwt)| digest(jwt)),
            expires_at: deadline,
        };
        // state 仅在一次性 launch 中使用；加密后与 PKCE 一起持久化，重启/多副本可恢复。
        let mut a = a;
        let verifier = self.open(&a.verifier_ciphertext, &a.id)?;
        a.verifier_ciphertext = self.seal(&format!("{state}:{verifier}"), &a.id)?;
        self.repo.identity_attempt_insert(&a).await?;
        Ok(OidcStartResponse {
            attempt_id,
            expires_in: deadline.saturating_sub(now()) as u64,
            launch_url: if native {
                None
            } else {
                Some(format!(
                    "{}/v1/auth/oidc/{id}/start?attempt={}&launch={launch}",
                    self.config.public_base_url.trim_end_matches('/'),
                    a.id
                ))
            },
            nonce: if native { Some(nonce) } else { None },
        })
    }
    pub async fn launch(&self, id: &str, attempt: &str, launch: &str, browser: &str) -> CoreResult<String> {
        self.limited("launch").await?;
        let p = self.provider(id)?;
        let a = self.repo.identity_attempt(attempt, false).await?.ok_or_else(denied)?;
        if a.provider != id
            || a.native
            || !self.repo.identity_launch(attempt, &digest(launch), &digest(browser), now()).await?
        {
            return Err(denied());
        }
        let d = self.discovery(p).await?;
        let binding = self.open(&a.verifier_ciphertext, &a.id)?;
        let (state, verifier) = binding.split_once(':').ok_or_else(denied)?;
        let mut u = url::Url::parse(&d.authorization_endpoint).map_err(|_| denied())?;
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &a.client_id)
            .append_pair("redirect_uri", &self.callback_url(id))
            .append_pair("state", state)
            .append_pair("nonce", &a.nonce);
        if p.kind == "apple" {
            q.append_pair("scope", "openid email name").append_pair("response_mode", "form_post");
        } else {
            q.append_pair("scope", "openid email profile")
                .append_pair("code_challenge", &challenge(verifier))
                .append_pair("code_challenge_method", "S256");
        }
        drop(q);
        Ok(u.into())
    }
    pub async fn callback(
        &self,
        id: &str,
        state: &str,
        browser: &str,
        code: &str,
        apple_user: Option<&str>,
    ) -> CoreResult<String> {
        self.limited("callback").await?;
        if code.is_empty() || code.len() > 8192 || state.len() > 128 {
            return Err(denied());
        }
        let p = self.provider(id)?;
        let a = self.repo.identity_attempt(&digest(state), true).await?.ok_or_else(denied)?;
        if a.native || a.provider != id || !self.repo.identity_claim(&a.id, id, &digest(browser), false, now()).await? {
            return Err(denied());
        }
        let d = self.discovery(p).await?;
        let client = network::client(p, &d.token_endpoint).await?;
        let binding = self.open(&a.verifier_ciphertext, &a.id)?;
        let (_, verifier) = binding.split_once(':').ok_or_else(denied)?;
        let mut params = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".into(), code.into()),
            ("client_id".into(), p.client_id.clone()),
            ("redirect_uri".into(), self.callback_url(id)),
        ];
        if p.kind != "apple" {
            params.push(("code_verifier".into(), verifier.into()));
        }
        let client_secret = if p.kind == "apple" { apple_client_secret(p, now())? } else { p.client_secret.clone() };
        let mut request = client.post(&d.token_endpoint);
        if p.token_auth_method == "client_secret_basic" {
            fn encoded(value: &str) -> String {
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("", value)
                    .finish()
                    .trim_start_matches('=')
                    .to_string()
            }
            request = request.basic_auth(encoded(&p.client_id), Some(encoded(&client_secret)));
            params.retain(|(k, _)| k != "client_id");
        } else if p.token_auth_method == "client_secret_post" && !client_secret.is_empty() {
            params.push(("client_secret".into(), client_secret));
        }

        let (tokens, _): (serde_json::Value, _) = network::json(
            request.form(&params).send().await.map_err(|_| CoreError::internal("OIDC code exchange failed"))?,
        )
        .await?;
        let token = tokens["id_token"].as_str().ok_or_else(denied)?;
        let claims = self.validate_id_token(id, token, &a.nonce, &a.client_id).await?;
        let credential = if p.kind == "apple" {
            Some(
                tokens["refresh_token"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| CoreError::invalid("Apple did not return a revocation credential"))?,
            )
        } else {
            None
        };
        let (tenant, user, generation, pending_identity) =
            self.resolve(&a, &claims, apple_user, credential, true).await?;
        let code = secret("lti_")?;
        self.repo
            .identity_handoff_insert(&LoginHandoff {
                attempt_id: Some(a.id.clone()),
                generation,
                pending_identity,
                link_session_hash: a.link_session_hash.clone(),
                hash: digest(&code),
                provider: id.into(),
                tenant_id: tenant,
                user_id: user,
                challenge: a.challenge,
                expires_at: now() + 60,
            })
            .await?;
        let mut uri = url::Url::parse(&a.return_uri).map_err(|_| denied())?;
        uri.query_pairs_mut().append_pair("code", &code).append_pair("state", &a.app_state);
        Ok(uri.into())
    }
    async fn resolve(
        &self,
        a: &LoginAttempt,
        c: &serde_json::Value,
        apple_user: Option<&str>,
        credential: Option<&str>,
        defer_link: bool,
    ) -> CoreResult<(String, String, i64, Option<String>)> {
        let p = self.provider(&a.provider)?;
        let verified =
            c["email_verified"].as_bool().unwrap_or(p.kind == "apple" && c["email_verified"].as_str() == Some("true"));
        let email = c["email"]
            .as_str()
            .filter(|s| s.len() <= 254 && s.contains('@') && !s.chars().any(char::is_control))
            .map(|s| s.trim().to_lowercase());
        let mut name = c["name"].as_str().and_then(sanitized_name);
        if p.kind == "apple"
            && let Some(payload) = apple_user
        {
            let v: serde_json::Value =
                serde_json::from_str(payload).map_err(|_| CoreError::invalid("invalid Apple name payload"))?;
            name = sanitized_name(&format!(
                "{} {}",
                v["name"]["firstName"].as_str().unwrap_or(""),
                v["name"]["lastName"].as_str().unwrap_or("")
            ));
        }
        let link = a.link_user.is_some();
        let tenant = a.link_tenant.clone().unwrap_or_else(memoswish_core::ids::new_id);
        let user = a.link_user.clone().unwrap_or_else(memoswish_core::ids::new_id);
        let identity = FederatedIdentity {
            client_id: a.client_id.clone(),
            issuer: p.issuer.clone(),
            subject: c["sub"].as_str().ok_or_else(denied)?.into(),
            provider: a.provider.clone(),
            tenant_id: tenant.clone(),
            user_id: user.clone(),
            email: email.clone(),
            email_verified: verified,
            display_name: name.clone(),
            created_at: now(),
            authenticated_at: c["iat"].as_i64().ok_or_else(denied)?,
        };
        let display = name.unwrap_or_else(|| format!("{} user", env!("BRAND_EN_PRODUCT")));
        let t = TenantRecord {
            id: tenant.clone(),
            name: display.clone(),
            plan: self.default_plan.clone(),
            created_at: Utc::now(),
        };
        // 仅验证邮箱写入密码登录索引；无邮箱/未验证邮箱不参与查找或合并。
        let u = UserRecord {
            id: user,
            tenant_id: tenant,
            email: if verified { email.unwrap_or_else(|| format!("oidc:{}", t.id)) } else { format!("oidc:{}", t.id) },
            display_name: display,
            password_hash: String::new(),
            role: Role::Owner,
            created_at: Utc::now(),
        };
        let encrypted = credential
            .map(|s| {
                let aad = format!("{}\0{}", p.issuer, identity.subject);
                self.seal(&serde_json::json!({"token":s,"client_id":a.client_id}).to_string(), &aad)
                    .map(|cipher| format!("{aad}\n{cipher}"))
            })
            .transpose()?;
        if link && defer_link {
            let pending = serde_json::to_string(&(identity, encrypted)).map_err(CoreError::internal)?;
            return Ok((t.id, u.id, a.link_generation.ok_or_else(denied)?, Some(self.seal(&pending, "pending-link")?)));
        }
        let (t, u, generation) = self
            .repo
            .identity_resolve(
                &identity,
                if self.auth.registration_open() && !link { Some((&t, &u)) } else { None },
                link,
                encrypted.as_deref(),
                a.link_generation
                    .zip(a.link_membership_generation)
                    .map(|(account, membership)| CredentialGenerations { account, membership }),
                Some(&a.id),
            )
            .await?;
        Ok((t, u, generation, None))
    }
    async fn complete_handoff(
        &self,
        id: &str,
        r: &OidcCompleteRequest,
        bearer: Option<&str>,
        link_only: bool,
    ) -> CoreResult<LoginHandoff> {
        self.limited("complete").await?;
        self.provider(id)?;
        validate_verifier(&r.code_verifier)?;
        let h = self
            .repo
            .identity_handoff_consume(&digest(&r.code), id, &challenge(&r.code_verifier), now())
            .await?
            .ok_or_else(denied)?;
        let attempt_id = h.attempt_id.as_deref().ok_or_else(denied)?;
        if link_only
            && (h.pending_identity.is_none() || !bearer.is_some_and(|t| t.starts_with(crate::sessions::ACCESS_PREFIX)))
        {
            return Err(denied());
        }
        if let Some(pending) = &h.pending_identity {
            let jwt = bearer.ok_or_else(denied)?;
            let principal = self.auth.authenticate(Some(jwt)).await?;
            self.auth.require_privacy_collection(&principal).await?;
            if !["jwt", "session"].contains(&principal.via.as_str())
                || principal.tenant_id != h.tenant_id
                || principal.user_id != h.user_id
                || principal.auth_generation != Some(h.generation)
                || h.link_session_hash.as_deref() != Some(digest(jwt).as_str())
            {
                return Err(denied());
            }
            let (identity, credential): (FederatedIdentity, Option<String>) =
                serde_json::from_str(&self.open(pending, "pending-link")?).map_err(|_| denied())?;
            self.repo
                .identity_resolve(
                    &identity,
                    None,
                    true,
                    credential.as_deref(),
                    Some(CredentialGenerations {
                        account: principal.auth_generation.ok_or_else(denied)?,
                        membership: principal.membership_generation.ok_or_else(denied)?,
                    }),
                    Some(attempt_id),
                )
                .await?;
        }
        Ok(h)
    }
    pub async fn complete(&self, id: &str, r: &OidcCompleteRequest, bearer: Option<&str>) -> CoreResult<AuthResponse> {
        let h = self.complete_handoff(id, r, bearer, false).await?;
        let user = self.repo.get_user(&h.tenant_id, &h.user_id).await?.ok_or_else(denied)?;
        self.auth
            .interactive_response_for_attempt(&user, h.generation, h.attempt_id.as_deref().ok_or_else(denied)?)
            .await
    }
    pub async fn complete_account(
        &self,
        id: &str,
        r: &OidcCompleteRequest,
        bearer: Option<&str>,
    ) -> CoreResult<AccountSessionResponse> {
        let h = self.complete_handoff(id, r, bearer, false).await?;
        let response = self.auth.account_response(&h.user_id, h.generation).await?;
        self.repo
            .identity_complete_account(
                h.attempt_id.as_deref().ok_or_else(denied)?,
                &h.tenant_id,
                &h.user_id,
                h.generation,
                &digest(&response.access_token),
                now(),
            )
            .await?;
        Ok(response)
    }
    async fn exchange_identity(&self, id: &str, r: &OidcExchangeRequest) -> CoreResult<(String, String, i64, String)> {
        self.limited("exchange").await?;
        validate_verifier(&r.code_verifier)?;
        let a = self.repo.identity_attempt(&r.attempt_id, false).await?.ok_or_else(denied)?;
        if !a.native
            || a.provider != id
            || !equal(&a.nonce, &r.nonce)
            || !equal(&a.challenge, &challenge(&r.code_verifier))
            || !self.repo.identity_claim(&a.id, id, &challenge(&a.challenge), true, now()).await?
        {
            return Err(denied());
        }
        let c = self.validate_id_token(id, &r.id_token, &a.nonce, &a.client_id).await?;
        let p = self.provider(id)?;
        let credential = if p.kind == "apple" {
            let code = r.authorization_code.as_ref().filter(|c| !c.is_empty() && c.len() <= 8192).ok_or_else(|| {
                CoreError::invalid("Apple native exchange requires an authorization code for revocation")
            })?;
            let d = self.discovery(p).await?;
            let client = network::client(p, &d.token_endpoint).await?;
            let mut profile = p.clone();
            profile.client_id = a.client_id.clone();
            let secret = apple_client_secret(&profile, now())?;
            let (tokens, _): (serde_json::Value, _) = network::json(
                client
                    .post(&d.token_endpoint)
                    .form(&[
                        ("grant_type", "authorization_code"),
                        ("code", code.as_str()),
                        ("client_id", a.client_id.as_str()),
                        ("client_secret", secret.as_str()),
                    ])
                    .send()
                    .await
                    .map_err(|_| CoreError::internal("Apple native code exchange failed"))?,
            )
            .await?;
            let returned = self
                .validate_id_token(id, tokens["id_token"].as_str().ok_or_else(denied)?, &a.nonce, &a.client_id)
                .await?;
            if returned["sub"] != c["sub"] {
                return Err(denied());
            }
            Some(
                tokens["refresh_token"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| CoreError::invalid("Apple did not return a revocation credential"))?
                    .to_string(),
            )
        } else {
            None
        };
        let (tenant, user, generation, _) =
            self.resolve(&a, &c, r.apple_user.as_deref(), credential.as_deref(), false).await?;
        Ok((tenant, user, generation, a.id))
    }
    pub async fn exchange(&self, id: &str, r: &OidcExchangeRequest) -> CoreResult<AuthResponse> {
        let (tenant, user, generation, attempt) = self.exchange_identity(id, r).await?;
        let user = self.repo.get_user(&tenant, &user).await?.ok_or_else(denied)?;
        self.auth.interactive_response_for_attempt(&user, generation, &attempt).await
    }
    pub async fn exchange_account(&self, id: &str, r: &OidcExchangeRequest) -> CoreResult<AccountSessionResponse> {
        let (tenant, user, generation, attempt) = self.exchange_identity(id, r).await?;
        let response = self.auth.account_response(&user, generation).await?;
        self.repo
            .identity_complete_account(&attempt, &tenant, &user, generation, &digest(&response.access_token), now())
            .await?;
        Ok(response)
    }
    pub async fn complete_session(
        &self,
        id: &str,
        r: &OidcCompleteRequest,
        bearer: Option<&str>,
    ) -> CoreResult<SessionResponse> {
        let h = self.complete_handoff(id, r, bearer, false).await?;
        self.auth
            .issue_session(&h.user_id, h.generation, "oidc", Some(h.attempt_id.as_deref().ok_or_else(denied)?))
            .await
    }
    pub async fn complete_link_ack(&self, id: &str, r: &OidcCompleteRequest, bearer: &str) -> CoreResult<()> {
        let h = self.complete_handoff(id, r, Some(bearer), true).await?;
        self.repo
            .session_link_ack(&crate::sessions::access_hash(bearer)?, h.attempt_id.as_deref().ok_or_else(denied)?)
            .await
    }
    pub async fn exchange_session(&self, id: &str, r: &OidcExchangeRequest) -> CoreResult<SessionResponse> {
        let (_, user, generation, attempt) = self.exchange_identity(id, r).await?;
        self.auth.issue_session(&user, generation, "oidc", Some(&attempt)).await
    }
    pub async fn revoke(&self, provider: &str, encrypted: &str) -> CoreResult<()> {
        let p = self.provider(provider)?;
        let d = self.discovery(p).await?;
        // 密文绑定 issuer/subject；删除任务中携带此绑定，以便身份行擦除后撤销。
        let (aad, ciphertext) =
            encrypted.split_once('\n').ok_or_else(|| CoreError::internal("invalid revocation envelope"))?;
        let raw = self.open(ciphertext, aad)?;
        let data: serde_json::Value = serde_json::from_str(&raw).map_err(|_| denied())?;
        let token = data["token"].as_str().ok_or_else(denied)?;
        let client_id = data["client_id"].as_str().ok_or_else(denied)?;
        if client_id != p.client_id && !p.native_client_ids.iter().any(|c| c == client_id) {
            return Err(denied());
        }
        let mut profile = p.clone();
        profile.client_id = client_id.into();
        let endpoint =
            d.revocation_endpoint.ok_or_else(|| CoreError::internal("OIDC revocation endpoint unavailable"))?;
        let client = network::client(p, &endpoint).await?;
        let secret = apple_client_secret(&profile, now())?;
        let response = client
            .post(endpoint)
            .form(&[
                ("client_id", client_id),
                ("client_secret", &secret),
                ("token", token),
                ("token_type_hint", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|_| CoreError::internal("upstream revocation request failed"))?;
        if !response.status().is_success() {
            return Err(CoreError::internal("upstream revocation failed"));
        }
        Ok(())
    }
}
pub fn validate_verifier(v: &str) -> CoreResult<()> {
    if !(43..=128).contains(&v.len()) || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)) {
        return Err(CoreError::invalid("invalid S256 verifier"));
    }
    Ok(())
}
/// Apple 客户端机密与上游 ID-token 使用不同算法和验证边界。
pub fn apple_client_secret(p: &OidcProvider, at: i64) -> CoreResult<String> {
    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        iat: i64,
        exp: i64,
    }
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(p.apple_key_id.clone());
    let pem = p.apple_private_key.trim();
    let data = pem
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|v| v.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or_else(|| CoreError::invalid("Apple key must be PKCS8 PEM"))?;
    if data.len() > 8192 {
        return Err(CoreError::invalid("Apple key exceeds size limit"));
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(data.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .map_err(|_| CoreError::invalid("invalid Apple signing key"))?;
    let key = EncodingKey::from_ec_der(&der);
    jsonwebtoken::encode(
        &header,
        &Claims { iss: &p.apple_team_id, sub: &p.client_id, aud: "https://appleid.apple.com", iat: at, exp: at + 300 },
        &key,
    )
    .map_err(|_| CoreError::internal("Apple client secret signing failed"))
}
