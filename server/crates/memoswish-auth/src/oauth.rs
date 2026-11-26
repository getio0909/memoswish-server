//! MCP 专用 OAuth 服务：浏览器同意、S256、令牌家族与受众隔离。

use crate::{AuthService, RateLimiter};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use memoswish_core::oauth::*;
use memoswish_core::repo::Repository;
use memoswish_core::{CoreError, CoreResult, Permission, Principal};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use url::{Host, Url};

pub const SCOPES: &[&str] =
    &["feed:read", "feedback:write", "content:read", "content:write", "media:read", "media:write", "tts:generate"];

pub use crate::oauth_config::OAuthConfig;

pub use crate::flow::{challenge, digest, equal, now, secret};
fn invalid(s: &str) -> CoreError {
    CoreError::invalid(s)
}
fn denied() -> CoreError {
    CoreError::Unauthorized("invalid OAuth credential or binding".into())
}

fn required<'a>(p: &'a HashMap<String, String>, key: &str) -> CoreResult<&'a str> {
    p.get(key).filter(|s| !s.is_empty()).map(String::as_str).ok_or_else(|| invalid("invalid_request"))
}

pub fn scopes(s: &str) -> CoreResult<Vec<String>> {
    let mut out = Vec::new();
    for word in s.split(' ') {
        if !SCOPES.contains(&word) {
            return Err(invalid("invalid_scope"));
        }
        if !out.iter().any(|x| x == word) {
            out.push(word.to_string());
        }
    }
    if out.is_empty() {
        return Err(invalid("invalid_scope"));
    }
    Ok(out)
}
fn loopback(u: &Url) -> bool {
    matches!(u.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(u.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
}
pub fn validate_redirect(s: &str) -> CoreResult<Url> {
    let u = Url::parse(s).map_err(|_| invalid("invalid_redirect_uri"))?;
    if s.len() > 2048
        || s.contains('*')
        || s.chars().any(char::is_control)
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || !(u.scheme() == "https" || u.scheme() == "http" && loopback(&u))
    {
        return Err(invalid("invalid_redirect_uri"));
    }
    Ok(u)
}
fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(mut a), Ok(mut b)) = (validate_redirect(registered), validate_redirect(requested)) else {
        return false;
    };
    if a.scheme() != "http" || b.scheme() != "http" || !loopback(&a) || !loopback(&b) {
        return false;
    }
    if a.as_str() != registered || b.as_str() != requested {
        return false;
    }
    let _ = a.set_port(None);
    let _ = b.set_port(None);
    a == b
}

#[derive(Debug, Deserialize)]
pub struct Registration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub scope: Option<String>,
}
#[derive(Clone)]
pub struct OAuthService {
    pub config: OAuthConfig,
    pub repo: Arc<dyn Repository>,
    pub auth: AuthService,
    pub limiter: Arc<dyn memoswish_core::rate_limit::RateLimiter>,
}
impl OAuthService {
    pub fn new(repo: Arc<dyn Repository>, auth: AuthService, config: OAuthConfig) -> CoreResult<Self> {
        config.validate()?;
        Ok(Self { repo, auth, config, limiter: Arc::new(RateLimiter::new(60, 1.0)) })
    }
    pub async fn register(&self, r: Registration) -> CoreResult<(OAuthClient, Option<String>)> {
        if !self.config.dynamic_registration {
            return Err(CoreError::Forbidden("dynamic registration disabled".into()));
        }
        let (c, plaintext) = self.prepare_client(r)?;
        self.repo.oauth_register(&c).await?;
        Ok((c, plaintext))
    }
    fn prepare_client(&self, r: Registration) -> CoreResult<(OAuthClient, Option<String>)> {
        if r.client_name.trim().is_empty()
            || r.client_name.len() > 128
            || r.client_name.chars().any(char::is_control)
            || r.redirect_uris.is_empty()
            || r.redirect_uris.len() > 8
        {
            return Err(invalid("invalid_client_metadata"));
        }
        for u in &r.redirect_uris {
            validate_redirect(u)?;
        }
        let auth_method = r.token_endpoint_auth_method.unwrap_or_else(|| "none".into());
        let grants = r.grant_types.unwrap_or_else(|| vec!["authorization_code".into()]);
        if !["none", "client_secret_basic", "client_secret_post"].contains(&auth_method.as_str())
            || !grants.iter().any(|s| s == "authorization_code")
            || grants.len() > 2
            || grants.iter().any(|s| s != "authorization_code" && s != "refresh_token")
            || r.response_types.is_some_and(|x| x != ["code"])
        {
            return Err(invalid("invalid_client_metadata"));
        }
        let allowed =
            scopes(r.scope.as_deref().unwrap_or(&SCOPES.join(" "))).map_err(|_| invalid("invalid_client_metadata"))?;
        let plaintext = if auth_method == "none" { None } else { Some(secret("lto_cs_")?) };
        let c = OAuthClient {
            id: secret("lto_client_")?,
            name: r.client_name,
            redirect_uris: r.redirect_uris,
            grant_types: grants,
            scopes: allowed,
            auth_method,
            secret_hash: plaintext.as_deref().map(digest),
            created_at: now(),
            expires_at: now() + 90 * 86400,
        };
        Ok((c, plaintext))
    }
    pub async fn install_clients(&self) -> CoreResult<()> {
        if self.config.pre_registered_clients.len() > 32 {
            return Err(invalid("too many pre-registered clients"));
        }
        let mut ids = std::collections::HashSet::new();
        for p in &self.config.pre_registered_clients {
            if p.client_id.is_empty()
                || p.client_id.len() > 128
                || !p.client_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                || !ids.insert(&p.client_id)
            {
                return Err(invalid("invalid or duplicate pre-registered client ID"));
            }
            let (mut c, _) = self.prepare_client(Registration {
                client_name: p.client_name.clone(),
                redirect_uris: p.redirect_uris.clone(),
                token_endpoint_auth_method: Some("none".into()),
                grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
                response_types: None,
                scope: Some(p.scope.clone()),
            })?;
            c.id = p.client_id.clone();
            if let Some(existing) = self.repo.oauth_client(&c.id).await? {
                c.created_at = existing.created_at;
                c.expires_at = existing.expires_at;
                if c != existing {
                    return Err(invalid("pre-registered client metadata changed; use a new client ID"));
                }
            } else {
                self.repo.oauth_register(&c).await?;
            }
        }
        Ok(())
    }
    pub async fn client(&self, id: &str) -> CoreResult<OAuthClient> {
        self.repo.oauth_client(id).await?.filter(|c| c.expires_at > now()).ok_or_else(denied)
    }
    /// 只有客户端及回调绑定通过校验后，HTTP 层才能向该回调发送授权错误。
    pub async fn authorization_client(&self, p: &HashMap<String, String>) -> CoreResult<OAuthClient> {
        let get = |k: &str| required(p, k);
        let c = self.client(get("client_id")?).await?;
        let redirect = get("redirect_uri")?;
        validate_redirect(redirect)?;
        if !c.redirect_uris.iter().any(|u| redirect_matches(u, redirect)) {
            return Err(invalid("invalid_redirect_uri"));
        }
        Ok(c)
    }
    pub async fn begin(&self, p: &HashMap<String, String>) -> CoreResult<(AuthorizationRequest, String, String)> {
        let c = self.authorization_client(p).await?;
        let get = |k: &str| required(p, k);
        let redirect = get("redirect_uri")?;
        if get("resource").ok() != Some(self.config.mcp_resource.as_str()) {
            return Err(invalid("invalid_target"));
        }
        if get("response_type")? != "code" {
            return Err(invalid("unsupported_response_type"));
        }
        if p.get("response_mode").is_some_and(|mode| !mode.is_empty() && mode != "query") {
            return Err(invalid("invalid_request"));
        }
        if get("code_challenge_method")? != "S256" {
            return Err(invalid("invalid_request"));
        }
        let ch = get("code_challenge")?;
        if ch.len() != 43 || URL_SAFE_NO_PAD.decode(ch).map_or(true, |b| b.len() != 32) {
            return Err(invalid("invalid_request"));
        }
        let requested = scopes(get("scope")?)?;
        if requested.iter().any(|s| !c.scopes.contains(s)) {
            return Err(invalid("invalid_scope"));
        }
        if p.get("state").is_some_and(|s| s.len() > 1024) {
            return Err(invalid("invalid_request"));
        }
        let cookie = secret("lto_bs_")?;
        let csrf = secret("lto_csrf_")?;
        let session = BrowserSession {
            hash: digest(&cookie),
            tenant_id: None,
            user_id: None,
            auth_time: 0,
            auth_method: "anonymous".into(),
            generations: None,
            expires_at: now() + 600,
        };
        let r = AuthorizationRequest {
            id: secret("lto_req_")?,
            browser_hash: session.hash.clone(),
            csrf_hash: digest(&csrf),
            client_id: c.id,
            redirect_uri: redirect.into(),
            resource: self.config.mcp_resource.clone(),
            scopes: requested,
            challenge: ch.into(),
            state: p.get("state").cloned(),
            expires_at: now() + 600,
        };
        self.repo.oauth_begin(&session, &r).await?;
        Ok((r, cookie, csrf))
    }
    pub async fn browser_request(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
    ) -> CoreResult<(AuthorizationRequest, BrowserSession)> {
        let r = self.repo.oauth_request(id).await?.ok_or_else(denied)?;
        if r.expires_at <= now() || !equal(&r.browser_hash, &digest(cookie)) || !equal(&r.csrf_hash, &digest(csrf)) {
            return Err(denied());
        }
        let s = self.repo.oauth_browser(&r.browser_hash).await?.filter(|s| s.expires_at > now()).ok_or_else(denied)?;
        Ok((r, s))
    }
    pub async fn login(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
        email: &str,
        password: &str,
    ) -> CoreResult<(AuthorizationRequest, String, Principal)> {
        let (mut r, s) = self.browser_request(id, cookie, csrf).await?;
        if s.tenant_id.is_some() || email.len() > 254 || password.len() > 1024 {
            return Err(denied());
        }
        let auth = self
            .auth
            .login(&memoswish_protocol::LoginRequest { email: email.into(), password: password.into() })
            .await?;
        let p = self.auth.authenticate(Some(&auth.access_token)).await?;
        let cookie = secret("lto_bs_")?;
        let s = BrowserSession {
            hash: digest(&cookie),
            tenant_id: Some(p.tenant_id.clone()),
            user_id: Some(p.user_id.clone()),
            auth_time: now(),
            auth_method: "password".into(),
            generations: Some(memoswish_core::CredentialGenerations {
                account: p.auth_generation.ok_or_else(denied)?,
                membership: p.membership_generation.ok_or_else(denied)?,
            }),
            expires_at: r.expires_at,
        };
        if !self.repo.oauth_login(&p.tenant_id, &r, &s, now()).await? {
            return Err(denied());
        }
        r.browser_hash = s.hash;
        Ok((r, cookie, p))
    }
    pub async fn consent(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
        approve: bool,
    ) -> CoreResult<(AuthorizationRequest, Option<String>)> {
        let (r, s) = self.browser_request(id, cookie, csrf).await?;
        let tenant = s.tenant_id.ok_or_else(denied)?;
        let user_id = s.user_id.ok_or_else(denied)?;
        self.client(&r.client_id).await?;
        let generations = s.generations.ok_or_else(denied)?;
        let role = self.repo.membership_authorize(&tenant, &user_id, generations).await?;
        if r.scopes.iter().any(|scope| !permissions().iter().any(|p| p.as_scope() == scope && role.allows(*p))) {
            return Err(CoreError::Forbidden("requested permissions exceed current user role".into()));
        }
        let plaintext = if approve { Some(secret("lto_code_")?) } else { None };
        let grant_id = secret("lto_grant_")?;
        let code = plaintext.as_ref().map(|s| AuthorizationCode {
            hash: digest(s),
            grant: OAuthGrant {
                generations,
                id: grant_id,
                tenant_id: tenant.clone(),
                user_id,
                client_id: r.client_id.clone(),
                resource: r.resource.clone(),
                scopes: r.scopes.clone(),
                expires_at: now() + self.config.refresh_token_ttl_secs,
            },
            redirect_uri: r.redirect_uri.clone(),
            challenge: r.challenge.clone(),
            expires_at: now() + self.config.authorization_code_ttl_secs,
        });
        if code.as_ref().is_some_and(|c| c.grant.id.is_empty()) {
            return Err(CoreError::internal("OS random generator unavailable"));
        }
        if !self.repo.oauth_consent(&tenant, &r, code.as_ref(), now()).await? {
            return Err(denied());
        }
        Ok((r, plaintext))
    }
    pub async fn authenticate(&self, token: &str, resource: &str) -> CoreResult<Principal> {
        if !token.starts_with("lto_at_") || token.len() > 128 {
            return Err(denied());
        }
        let t = self.repo.oauth_token(&digest(token)).await?.ok_or_else(denied)?;
        if t.kind != "access"
            || t.expires_at <= now()
            || t.grant.expires_at <= now()
            || t.grant.resource != resource
            || resource != self.config.mcp_resource
        {
            return Err(denied());
        }
        self.client(&t.grant.client_id).await?;
        let role = self.repo.membership_authorize(&t.grant.tenant_id, &t.grant.user_id, t.grant.generations).await?;
        Ok(Principal {
            tenant_id: t.grant.tenant_id,
            user_id: t.grant.user_id,
            role,
            scopes: Some(t.scopes),
            via: "mcp_oauth".into(),
            session_access_hash: Some(format!("oauth:{}", t.hash)),
            auth_generation: Some(t.grant.generations.account),
            membership_generation: Some(t.grant.generations.membership),
            legacy_issued_at: None,
        })
    }
    pub fn issue(
        &self,
        grant: &OAuthGrant,
        scopes: Vec<String>,
        refresh_scopes: Option<Vec<String>>,
    ) -> CoreResult<(TokenResponse, Vec<OAuthToken>)> {
        let access = secret("lto_at_")?;
        let exp = (now() + self.config.access_token_ttl_secs).min(grant.expires_at);
        let mut rows = vec![OAuthToken {
            hash: digest(&access),
            grant: grant.clone(),
            scopes: scopes.clone(),
            kind: "access".into(),
            expires_at: exp,
        }];
        let rt = if let Some(refresh_scopes) = refresh_scopes {
            let s = secret("lto_rt_")?;
            rows.push(OAuthToken {
                hash: digest(&s),
                grant: grant.clone(),
                scopes: refresh_scopes,
                kind: "refresh".into(),
                expires_at: grant.expires_at,
            });
            Some(s)
        } else {
            None
        };
        Ok((
            TokenResponse {
                access_token: access,
                token_type: "Bearer",
                expires_in: exp - now(),
                refresh_token: rt,
                scope: scopes.join(" "),
            },
            rows,
        ))
    }
    pub async fn exchange(&self, c: &OAuthClient, p: &HashMap<String, String>) -> CoreResult<TokenResponse> {
        if p.get("resource") != Some(&self.config.mcp_resource) {
            return Err(invalid("invalid_target"));
        }
        let grant_type = required(p, "grant_type")?;
        if !["authorization_code", "refresh_token"].contains(&grant_type) {
            return Err(invalid("unsupported_grant_type"));
        }
        if !c.grant_types.iter().any(|s| s == grant_type) {
            return Err(invalid("unauthorized_client"));
        }
        let (grant, allowed, code, parent) = match grant_type {
            "authorization_code" => {
                let raw = required(p, "code")?;
                let v = required(p, "code_verifier")?;
                if !raw.starts_with("lto_code_") {
                    return Err(denied());
                }
                let code = self.repo.oauth_code(&digest(raw)).await?.ok_or_else(denied)?;
                // 到期检查留在消费事务内，使已消费但到期的码仍能触发重用撤销。
                if code.grant.expires_at <= now()
                    || code.grant.client_id != c.id
                    || code.grant.resource != self.config.mcp_resource
                    || p.get("redirect_uri").is_some_and(|uri| uri != &code.redirect_uri)
                    || !(43..=128).contains(&v.len())
                    || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                    || !equal(&challenge(v), &code.challenge)
                {
                    return Err(denied());
                }
                (code.grant.clone(), code.grant.scopes.clone(), Some(code), None)
            }
            "refresh_token" => {
                let raw = required(p, "refresh_token")?;
                if !raw.starts_with("lto_rt_") {
                    return Err(denied());
                }
                let parent = self.repo.oauth_token(&digest(raw)).await?.ok_or_else(denied)?;
                if parent.kind != "refresh"
                    || parent.expires_at <= now()
                    || parent.grant.expires_at <= now()
                    || parent.grant.client_id != c.id
                    || parent.grant.resource != self.config.mcp_resource
                {
                    return Err(denied());
                }
                (parent.grant.clone(), parent.scopes.clone(), None, Some(parent))
            }
            _ => return Err(invalid("unsupported_grant_type")),
        };
        let wanted = match p.get("scope").filter(|s| !s.is_empty()) {
            Some(s) => scopes(s)?,
            None => allowed.clone(),
        };
        if wanted.iter().any(|s| !allowed.contains(s)) {
            return Err(invalid("invalid_scope"));
        }
        let user = self.repo.get_user(&grant.tenant_id, &grant.user_id).await?.ok_or_else(denied)?;
        if wanted.iter().any(|s| !permissions().iter().any(|p| p.as_scope() == s && user.role.allows(*p))) {
            return Err(invalid("invalid_scope"));
        }
        // 访问令牌可收窄，但轮换必须保留父刷新令牌的范围，包括旧版本写入的窄范围。
        let refresh_scopes = c.grant_types.iter().any(|s| s == "refresh_token").then_some(allowed);
        let (response, rows) = self.issue(&grant, wanted, refresh_scopes)?;
        let ok = if let Some(code) = code {
            self.repo.oauth_redeem(&grant.tenant_id, &code, &rows, now()).await?
        } else {
            self.repo.oauth_rotate(&grant.tenant_id, &parent.ok_or_else(denied)?, &rows, now()).await?
        };
        if !ok {
            return Err(denied());
        }
        Ok(response)
    }
}
pub fn permissions() -> [Permission; 7] {
    [
        Permission::FeedRead,
        Permission::FeedbackWrite,
        Permission::ContentRead,
        Permission::ContentWrite,
        Permission::MediaRead,
        Permission::MediaWrite,
        Permission::TtsGenerate,
    ]
}
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
}
