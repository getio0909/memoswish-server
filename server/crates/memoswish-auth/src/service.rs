//! 认证服务：注册、登录、Bearer 解析、API Token 管理、单用户模式引导。

use std::sync::Arc;

use chrono::{Duration, Utc};
use memoswish_core::ids::{LOCAL_TENANT_ID, LOCAL_USER_ID, new_id};
use memoswish_core::repo::{ApiTokenRecord, Repository, TenantRecord, UserRecord};
use memoswish_core::{AccountPrincipal, CoreError, CoreResult, CredentialGenerations, Permission, Principal, Role};
use memoswish_protocol::{AuthResponse, DeploymentMode, LoginRequest, RegisterRequest, UserProfile};

use crate::password::{PasswordConfig, PasswordRunner};
use crate::token::{API_TOKEN_PREFIX, JwtCodec, generate_api_token, hash_api_token};

/// 认证配置。
#[derive(Clone)]
pub struct AuthConfig {
    pub mode: DeploymentMode,
    /// HS256 密钥（≥ 32 字节）。
    pub jwt_secret: String,
    pub jwt_ttl_secs: u64,
    /// 是否允许自助注册（仅多租户模式有效）。
    pub registration_open: bool,
    /// 新注册租户的默认套餐。
    pub default_plan: String,
}

/// 新建 API Token 的结果（明文仅此一次可见）。
#[derive(Debug, Clone)]
pub struct CreatedToken {
    pub plaintext: String,
    pub record: ApiTokenRecord,
}

/// 所有合法的 scope 字符串。
pub const ALL_SCOPES: &[&str] = &[
    "*",
    "feed:read",
    "feedback:write",
    "content:read",
    "content:write",
    "media:read",
    "media:write",
    "tts:generate",
    "token:manage",
    "member:manage",
    "billing:manage",
    "account:export",
];

/// 认证服务。
#[derive(Clone)]
pub struct AuthService {
    pub(crate) repo: Arc<dyn Repository>,
    pub(super) cfg: AuthConfig,
    jwt: JwtCodec,
    pub(crate) passwords: PasswordRunner,
    pub(crate) password_enabled: bool,
    pub(crate) password_mail: Option<Arc<dyn crate::password_lifecycle::PasswordMail>>,
    pub(crate) privacy_policy: memoswish_protocol::PrivacyPolicy,
    pub(crate) session_config: crate::sessions::SessionConfig,
    #[cfg(feature = "test-support")]
    login_proof_gate: Option<Arc<crate::password_lifecycle::LoginProofGate>>,
}

impl AuthService {
    /// 提取已验证凭据的非秘密身份，恢复时不保存 bearer。
    pub fn import_credential(
        &self,
        p: &Principal,
        bearer: Option<&str>,
    ) -> CoreResult<memoswish_core::imports::ImportCredential> {
        let mut evidence = memoswish_core::imports::ImportCredential::default();
        // stdio 已完成认证，只保留主体中的原始摘要或期限，不要求再次保存 bearer。
        if bearer.is_none() && matches!(p.via.as_str(), "api_token" | "mcp_oauth" | "jwt") {
            let stored = p.session_access_hash.as_deref().unwrap_or_default();
            match p.via.as_str() {
                "api_token" | "mcp_oauth" => {
                    let prefix = if p.via == "api_token" { "api:" } else { "oauth:" };
                    let hash = stored
                        .strip_prefix(prefix)
                        .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
                        .ok_or_else(|| {
                            CoreError::Unauthorized("original import credential evidence is missing".into())
                        })?;
                    evidence.token_hash = Some(hash.into());
                }
                _ => {
                    evidence.expires_at = stored.strip_prefix("jwt:").and_then(|s| s.parse().ok());
                    if evidence.expires_at.is_none() || p.legacy_issued_at.is_none() {
                        return Err(CoreError::Unauthorized("original JWT deadline evidence is missing".into()));
                    }
                }
            }
            evidence.expires_at =
                evidence.expires_at.map(|exp| exp.min(self.session_config.legacy_verify_until.unwrap_or(exp)));
            return Ok(evidence);
        }
        if p.via == "api_token" {
            evidence.token_hash = Some(hash_api_token(
                bearer.ok_or_else(|| CoreError::Unauthorized("original credential is missing".into()))?,
            ));
        }
        if p.via == "mcp_oauth" {
            #[cfg(feature = "mcp-oauth")]
            {
                evidence.token_hash = Some(crate::flow::digest(
                    bearer.ok_or_else(|| CoreError::Unauthorized("original OAuth credential is missing".into()))?,
                ));
            }
            #[cfg(not(feature = "mcp-oauth"))]
            {
                return Err(CoreError::Unauthorized("OAuth import capability is unavailable".into()));
            }
        }
        if p.via == "jwt" {
            let claims =
                self.jwt.verify(bearer.ok_or_else(|| CoreError::Unauthorized("original JWT is missing".into()))?)?;
            if claims.sub != p.user_id
                || claims.tid != p.tenant_id
                || Some(claims.iat) != p.legacy_issued_at
                || Some(claims.generation) != p.auth_generation
                || Some(claims.membership_generation) != p.membership_generation
            {
                return Err(CoreError::Unauthorized("JWT evidence mismatch".into()));
            }
            evidence.expires_at = Some(claims.exp.min(self.session_config.legacy_verify_until.unwrap_or(claims.exp)));
        }
        Ok(evidence)
    }
    pub fn new(repo: Arc<dyn Repository>, cfg: AuthConfig) -> CoreResult<Self> {
        let jwt = JwtCodec::new(cfg.jwt_secret.as_bytes(), cfg.jwt_ttl_secs)?;
        Ok(Self {
            repo,
            cfg,
            jwt,
            passwords: PasswordRunner::new(PasswordConfig::default())?,
            password_enabled: true,
            password_mail: None,
            privacy_policy: Default::default(),
            session_config: Default::default(),
            #[cfg(feature = "test-support")]
            login_proof_gate: None,
        })
    }

    pub fn with_observer(mut self, observer: Arc<dyn memoswish_core::observability::Observer>) -> Self {
        self.passwords = self.passwords.with_observer(observer);
        self
    }

    pub fn with_password_config(mut self, config: PasswordConfig) -> CoreResult<Self> {
        self.passwords = PasswordRunner::new(config)?;
        Ok(self)
    }

    /// 所有克隆共享关闭边界；新密码计算返回可重试的不可用错误。
    pub fn close_password_work(&self) {
        self.passwords.close();
    }

    /// 宿主以自己的 shutdown deadline 限制等待，不中断实际 Argon2 计算。
    pub async fn wait_for_password_work(&self) {
        self.passwords.wait().await;
    }

    pub fn with_jwt_keys(
        mut self,
        active: Option<&str>,
        keys: std::collections::BTreeMap<String, crate::token::VerificationKey>,
        legacy_until: Option<i64>,
    ) -> CoreResult<Self> {
        self.jwt = self.jwt.with_keys(active, keys, legacy_until)?;
        Ok(self)
    }
    pub fn mode(&self) -> DeploymentMode {
        self.cfg.mode
    }

    pub fn registration_open(&self) -> bool {
        self.cfg.mode == DeploymentMode::MultiTenant && self.cfg.registration_open && !self.privacy_policy.hosted
    }

    /// 确保本地租户与本地所有者存在（单用户模式启动时调用，幂等）。
    pub async fn bootstrap_local(&self) -> CoreResult<()> {
        if self.repo.account_erased_tenant(LOCAL_TENANT_ID).await? {
            return Ok(());
        }
        if self.repo.get_tenant(LOCAL_TENANT_ID).await?.is_none() {
            self.repo
                .upsert_tenant(&TenantRecord {
                    id: LOCAL_TENANT_ID.into(),
                    name: "Local".into(),
                    plan: "self_hosted".into(),
                    created_at: Utc::now(),
                })
                .await?;
        }
        if self.repo.get_user(LOCAL_TENANT_ID, LOCAL_USER_ID).await?.is_none() {
            self.repo
                .insert_user(&UserRecord {
                    id: LOCAL_USER_ID.into(),
                    tenant_id: LOCAL_TENANT_ID.into(),
                    email: "owner@localhost".into(),
                    display_name: "Local Owner".into(),
                    password_hash: String::new(),
                    role: Role::Owner,
                    created_at: Utc::now(),
                })
                .await?;
        }
        Ok(())
    }

    /// 自助注册：创建新租户与所有者。
    pub async fn register(&self, req: &RegisterRequest) -> CoreResult<AuthResponse> {
        let (tenant, user) = self.prepare_registration(req).await?;
        self.repo.upsert_tenant(&tenant).await?;
        self.repo.insert_user(&user).await?;
        tracing::info!(target: "memoswish::auth::service", tenant_id = %tenant.id, user_id = %user.id, "tenant registered");
        self.interactive_response(&user).await
    }

    pub(crate) async fn prepare_registration(&self, req: &RegisterRequest) -> CoreResult<(TenantRecord, UserRecord)> {
        self.require_password_profile()?;
        if !self.registration_open() {
            return Err(CoreError::Forbidden("registration is closed".into()));
        }
        let email = normalized_email(&req.email)?;
        if !email.contains('@') || email.len() > 254 {
            return Err(CoreError::invalid("invalid email"));
        }
        if req.display_name.trim().is_empty() {
            return Err(CoreError::invalid("display_name is required"));
        }
        let password_hash = self.passwords.hash(&req.password).await?;
        let tenant = TenantRecord {
            id: new_id(),
            name: req.tenant_name.clone().unwrap_or_else(|| req.display_name.clone()),
            plan: self.cfg.default_plan.clone(),
            created_at: Utc::now(),
        };
        let user = UserRecord {
            id: new_id(),
            tenant_id: tenant.id.clone(),
            email,
            display_name: req.display_name.trim().into(),
            password_hash,
            role: Role::Owner,
            created_at: Utc::now(),
        };
        Ok((tenant, user))
    }

    /// 邮箱密码登录。
    pub async fn login(&self, req: &LoginRequest) -> CoreResult<AuthResponse> {
        let proof = self.verified_password(&req.email, &req.password).await?;
        #[cfg(feature = "test-support")]
        if let Some(gate) = &self.login_proof_gate {
            gate.pause().await;
        }
        let user = self
            .repo
            .find_user_by_email(&proof.email)
            .await?
            // 邮箱可以在销户后复用，签发只能沿用原口令证明绑定的账户。
            .filter(|user| user.id == proof.user_id)
            .ok_or_else(|| CoreError::Unauthorized("invalid email or password".into()))?;
        self.interactive_response_at_generation(&user, proof.generation).await
    }

    #[cfg(feature = "test-support")]
    pub fn with_login_proof_gate(mut self, gate: Arc<crate::password_lifecycle::LoginProofGate>) -> Self {
        self.login_proof_gate = Some(gate);
        self
    }

    /// 只有实际交互登录记录五分钟关联权限；刷新不会延长该窗口。
    pub async fn interactive_response(&self, u: &UserRecord) -> CoreResult<AuthResponse> {
        let generation = self.repo.account_generation(&u.id).await?;
        self.interactive_response_at_generation(u, generation).await
    }

    /// 交接沿用事务内验证的世代，撤销并发发生时只能失效，不能升级。
    pub async fn interactive_response_at_generation(
        &self,
        u: &UserRecord,
        generation: i64,
    ) -> CoreResult<AuthResponse> {
        let (response, generations) = self.auth_response(u, generation).await?;
        self.repo
            .identity_recent_auth(
                &u.tenant_id,
                &u.id,
                generations,
                &memoswish_core::ids::sha256_hex(response.access_token.as_bytes()),
                Utc::now().timestamp() + 300,
            )
            .await?;
        Ok(response)
    }

    /// OIDC 完成与解绑共享事务锁，只有身份归属仍有效时才提交交互认证。
    #[cfg(feature = "oidc")]
    pub(crate) async fn interactive_response_for_attempt(
        &self,
        u: &UserRecord,
        generation: i64,
        attempt_id: &str,
    ) -> CoreResult<AuthResponse> {
        let (response, generations) = self.auth_response(u, generation).await?;
        self.repo
            .identity_complete(
                attempt_id,
                &u.tenant_id,
                &u.id,
                generations,
                &memoswish_core::ids::sha256_hex(response.access_token.as_bytes()),
                Utc::now().timestamp(),
            )
            .await?;
        Ok(response)
    }

    async fn auth_response(
        &self,
        u: &UserRecord,
        generation: i64,
    ) -> CoreResult<(AuthResponse, CredentialGenerations)> {
        let membership = self
            .repo
            .memberships(&u.id)
            .await?
            .into_iter()
            .find(|m| m.tenant_id == u.tenant_id)
            .ok_or_else(|| CoreError::Unauthorized("membership no longer exists".into()))?;
        let generations = CredentialGenerations { account: generation, membership: membership.generation };
        Ok((self.workspace_response(u, generations).await?, generations))
    }

    async fn workspace_response(&self, u: &UserRecord, g: CredentialGenerations) -> CoreResult<AuthResponse> {
        self.legacy_allowed()?;
        let mut current = u.clone();
        current.role = self.repo.membership_authorize(&u.tenant_id, &u.id, g).await?;
        let generation = g.account;
        if generation != self.repo.account_generation(&u.id).await? {
            return Err(CoreError::Unauthorized("app session was revoked".into()));
        }
        Ok(AuthResponse {
            access_token: self.jwt.issue_workspace(
                &u.id,
                &u.tenant_id,
                current.role.as_str(),
                generation,
                g.membership,
            )?,
            token_type: "Bearer".into(),
            expires_in: self.jwt.ttl_secs(),
            user: profile_of(&current),
        })
    }

    /// 解析 `Authorization: Bearer ...` 的值（不含 `Bearer ` 前缀）为调用主体。
    pub async fn authenticate(&self, bearer: Option<&str>) -> CoreResult<Principal> {
        let token = bearer.map(str::trim).filter(|t| !t.is_empty());
        match token {
            None if self.cfg.mode == DeploymentMode::SingleUser => self.local_principal("single_user").await,
            None => Err(CoreError::Unauthorized("missing bearer token".into())),
            Some(t) if t.starts_with(API_TOKEN_PREFIX) => self.authenticate_api_token(t).await,
            Some(t) if t.starts_with(crate::sessions::ACCESS_PREFIX) => {
                let a = self.repo.session_access(&crate::sessions::access_hash(t)?).await?;
                let tid = a
                    .credential
                    .tenant_id
                    .ok_or_else(|| CoreError::Unauthorized("workspace session required".into()))?;
                let membership = a
                    .credential
                    .membership_generation
                    .ok_or_else(|| CoreError::Unauthorized("workspace session required".into()))?;
                let role = self
                    .repo
                    .membership_authorize(
                        &tid,
                        &a.family.user_id,
                        CredentialGenerations { account: a.family.generation, membership },
                    )
                    .await?;
                Ok(Principal {
                    tenant_id: tid,
                    user_id: a.family.user_id,
                    role,
                    scopes: None,
                    via: "session".into(),
                    session_access_hash: Some(a.credential.access_hash),
                    auth_generation: Some(a.family.generation),
                    membership_generation: Some(membership),
                    legacy_issued_at: None,
                })
            }
            Some(t) => {
                self.legacy_allowed()?;
                let claims = self.jwt.verify(t)?;
                self.repo
                    .legacy_session_authorize(
                        &claims.sub,
                        claims.generation,
                        claims.iat,
                        None,
                        Some((&claims.tid, claims.membership_generation)),
                    )
                    .await?;
                let role = self
                    .repo
                    .membership_authorize(
                        &claims.tid,
                        &claims.sub,
                        CredentialGenerations { account: claims.generation, membership: claims.membership_generation },
                    )
                    .await?;
                Ok(Principal {
                    tenant_id: claims.tid,
                    user_id: claims.sub,
                    role,
                    scopes: None,
                    via: "jwt".into(),
                    session_access_hash: Some(format!("jwt:{}", claims.exp)),
                    auth_generation: Some(claims.generation),
                    membership_generation: Some(claims.membership_generation),
                    legacy_issued_at: Some(claims.iat),
                })
            }
        }
    }

    /// 仅供可信本机 stdio 会话启动时捕获授权，后续请求沿用快照，不刷新世代。
    pub async fn authenticate_local_stdio(&self) -> CoreResult<Principal> {
        self.local_principal("stdio").await
    }

    async fn local_principal(&self, via: &str) -> CoreResult<Principal> {
        if self.repo.get_user(LOCAL_TENANT_ID, LOCAL_USER_ID).await?.is_none() {
            return Err(CoreError::Unauthorized("local account was erased".into()));
        }
        let generation = self.repo.account_generation(LOCAL_USER_ID).await?;
        let membership = self
            .repo
            .memberships(LOCAL_USER_ID)
            .await?
            .into_iter()
            .find(|m| m.tenant_id == LOCAL_TENANT_ID)
            .ok_or_else(|| CoreError::Unauthorized("local membership was erased".into()))?;
        let role = self
            .repo
            .membership_authorize(
                LOCAL_TENANT_ID,
                LOCAL_USER_ID,
                CredentialGenerations { account: generation, membership: membership.generation },
            )
            .await?;
        Ok(Principal {
            auth_generation: Some(generation),
            membership_generation: Some(membership.generation),
            role,
            ..Principal::local_owner(via)
        })
    }

    async fn authenticate_api_token(&self, plaintext: &str) -> CoreResult<Principal> {
        let rec = self
            .repo
            .find_api_token(&hash_api_token(plaintext))
            .await?
            .ok_or_else(|| CoreError::Unauthorized("unknown api token".into()))?;
        if rec.revoked {
            return Err(CoreError::Unauthorized("api token revoked".into()));
        }
        if rec.expires_at.is_some_and(|e| e < Utc::now()) {
            return Err(CoreError::Unauthorized("api token expired".into()));
        }
        let role = self.repo.membership_authorize(&rec.tenant_id, &rec.user_id, rec.generations).await?;
        // 最近使用时间仅用于审计，失败不影响认证。
        if let Err(e) = self.repo.touch_api_token(&rec.id, Utc::now()).await {
            tracing::warn!(target: "memoswish::auth::service", error = %e, "failed to update api token last_used_at");
        }
        Ok(Principal {
            tenant_id: rec.tenant_id,
            user_id: rec.user_id,
            role,
            scopes: Some(rec.scopes),
            via: "api_token".into(),
            session_access_hash: Some(format!("api:{}", rec.token_hash)),
            auth_generation: Some(rec.generations.account),
            membership_generation: Some(rec.generations.membership),
            legacy_issued_at: None,
        })
    }

    /// 为调用者本人创建 API Token。单用户模式下 CLI 以本地所有者身份调用。
    pub async fn create_api_token(
        &self,
        principal: &Principal,
        name: &str,
        scopes: Vec<String>,
        ttl_days: Option<i64>,
    ) -> CoreResult<CreatedToken> {
        principal.require(Permission::TokenManage)?;
        if name.trim().is_empty() {
            return Err(CoreError::invalid("token name is required"));
        }
        let scopes = if scopes.is_empty() { vec!["*".to_string()] } else { scopes };
        if let Some(bad) = scopes.iter().find(|s| !ALL_SCOPES.contains(&s.as_str())) {
            return Err(CoreError::invalid(format!("unknown scope `{bad}`")));
        }
        // API Token 不能获得超过创建者本身的权限。
        if principal.scopes.is_some() && scopes.iter().any(|s| s == "*") {
            return Err(CoreError::Forbidden("scoped tokens cannot mint wildcard tokens".into()));
        }
        if let Some(allowed) = &principal.scopes
            && !allowed.iter().any(|s| s == "*")
            && scopes.iter().any(|s| !allowed.contains(s))
        {
            return Err(CoreError::Forbidden("token scopes exceed caller scopes".into()));
        }
        let generations = CredentialGenerations {
            account: principal
                .auth_generation
                .ok_or_else(|| CoreError::Unauthorized("missing account generation".into()))?,
            membership: principal
                .membership_generation
                .ok_or_else(|| CoreError::Unauthorized("missing membership generation".into()))?,
        };
        let role = self.repo.membership_authorize(&principal.tenant_id, &principal.user_id, generations).await?;
        if !role.allows(Permission::TokenManage) {
            return Err(CoreError::Forbidden("token management requires current permission".into()));
        }
        let plaintext = generate_api_token();
        let now = Utc::now();
        let record = ApiTokenRecord {
            generations,
            id: new_id(),
            tenant_id: principal.tenant_id.clone(),
            user_id: principal.user_id.clone(),
            name: name.trim().into(),
            token_hash: hash_api_token(&plaintext),
            scopes,
            created_at: now,
            expires_at: ttl_days.map(|d| now + Duration::days(d)),
            last_used_at: None,
            revoked: false,
        };
        self.repo.issue_api_token(&record).await?;
        Ok(CreatedToken { plaintext, record })
    }

    pub async fn login_account(&self, req: &LoginRequest) -> CoreResult<memoswish_protocol::AccountSessionResponse> {
        let proof = self.verified_password(&req.email, &req.password).await?;
        self.account_response(&proof.user_id, proof.generation).await
    }

    pub async fn authenticate_account(&self, token: &str) -> CoreResult<AccountPrincipal> {
        if token.starts_with(crate::sessions::ACCESS_PREFIX) {
            let a = self.repo.session_access(&crate::sessions::access_hash(token)?).await?;
            if a.credential.tenant_id.is_some() {
                return Err(CoreError::Unauthorized("account session required".into()));
            }
            return Ok(AccountPrincipal {
                session_id: Some(a.family.id),
                session_access_hash: Some(a.credential.access_hash),
                legacy_issued_at: None,
                user_id: a.family.user_id,
                generation: a.family.generation,
            });
        }
        self.legacy_allowed()?;
        let claims = self.jwt.verify_account(token)?;
        self.repo.legacy_session_authorize(&claims.sub, claims.generation, claims.iat, None, None).await?;
        if self.repo.account_generation(&claims.sub).await? != claims.generation {
            return Err(CoreError::Unauthorized("account session was revoked".into()));
        }
        Ok(AccountPrincipal {
            session_id: None,
            session_access_hash: None,
            legacy_issued_at: Some(claims.iat),
            user_id: claims.sub,
            generation: claims.generation,
        })
    }

    pub async fn account_response(
        &self,
        user_id: &str,
        generation: i64,
    ) -> CoreResult<memoswish_protocol::AccountSessionResponse> {
        self.legacy_allowed()?;
        if self.repo.account_generation(user_id).await? != generation {
            return Err(CoreError::Unauthorized("account session was revoked".into()));
        }
        let account = self
            .repo
            .account_by_id(user_id)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("account no longer exists".into()))?;
        Ok(memoswish_protocol::AccountSessionResponse {
            access_token: self.jwt.issue_account(user_id, generation)?,
            token_type: "Bearer".into(),
            expires_in: self.jwt.ttl_secs(),
            account: memoswish_protocol::AccountProfile {
                user_id: account.id,
                email: account.email,
                display_name: account.display_name,
            },
        })
    }

    pub async fn select_workspace(&self, p: &AccountPrincipal, tenant_id: &str) -> CoreResult<AuthResponse> {
        if p.session_id.is_some() {
            return Err(CoreError::Unauthorized("use the opaque workspace endpoint".into()));
        }
        let membership = self
            .repo
            .memberships(&p.user_id)
            .await?
            .into_iter()
            .find(|m| m.tenant_id == tenant_id)
            .ok_or_else(|| CoreError::Unauthorized("membership no longer exists".into()))?;
        let user = self
            .repo
            .get_user(tenant_id, &p.user_id)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("membership no longer exists".into()))?;
        let response = self
            .workspace_response(
                &user,
                CredentialGenerations { account: p.generation, membership: membership.generation },
            )
            .await?;
        self.validate_legacy_successor(
            &p.user_id,
            p.generation,
            p.legacy_issued_at,
            &response.access_token,
            Some((tenant_id, membership.generation)),
        )
        .await?;
        Ok(response)
    }

    /// 当前用户概要。
    pub async fn profile(&self, principal: &Principal) -> CoreResult<UserProfile> {
        let u = self
            .repo
            .get_user(&principal.tenant_id, &principal.user_id)
            .await?
            .ok_or_else(|| CoreError::NotFound("user".into()))?;
        Ok(profile_of(&u))
    }

    /// 刷新已认证主体的 JWT 访问令牌。
    pub async fn refresh(&self, p: &Principal) -> CoreResult<AuthResponse> {
        self.legacy_allowed()?;
        if p.scopes.is_some()
            || !(p.via == "jwt" || (p.via == "single_user" && self.cfg.mode == DeploymentMode::SingleUser))
        {
            return Err(CoreError::Forbidden("only unrestricted app sessions can refresh app JWTs".into()));
        }
        let user = self
            .repo
            .get_user(&p.tenant_id, &p.user_id)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("user no longer exists".into()))?;
        let generations = CredentialGenerations {
            account: p.auth_generation.ok_or_else(|| CoreError::Unauthorized("missing account generation".into()))?,
            membership: p
                .membership_generation
                .ok_or_else(|| CoreError::Unauthorized("missing membership generation".into()))?,
        };
        let response = self.workspace_response(&user, generations).await?;
        if p.via == "jwt" {
            self.validate_legacy_successor(
                &p.user_id,
                generations.account,
                p.legacy_issued_at,
                &response.access_token,
                Some((&p.tenant_id, generations.membership)),
            )
            .await?;
        }
        Ok(response)
    }

    async fn validate_legacy_successor(
        &self,
        user: &str,
        generation: i64,
        original_iat: Option<i64>,
        token: &str,
        workspace: Option<(&str, i64)>,
    ) -> CoreResult<()> {
        let original_iat =
            original_iat.ok_or_else(|| CoreError::Unauthorized("missing legacy session evidence".into()))?;
        let successor_iat =
            if workspace.is_some() { self.jwt.verify(token)?.iat } else { self.jwt.verify_account(token)?.iat };
        self.repo.legacy_session_authorize(user, generation, original_iat, Some(successor_iat), workspace).await
    }

    pub async fn refresh_account(
        &self,
        p: &AccountPrincipal,
    ) -> CoreResult<memoswish_protocol::AccountSessionResponse> {
        if p.session_id.is_some() {
            return Err(CoreError::Unauthorized("refresh token required".into()));
        }
        let response = self.account_response(&p.user_id, p.generation).await?;
        self.validate_legacy_successor(&p.user_id, p.generation, p.legacy_issued_at, &response.access_token, None)
            .await?;
        Ok(response)
    }
}

pub(crate) fn profile_of(u: &UserRecord) -> UserProfile {
    UserProfile {
        user_id: u.id.clone(),
        tenant_id: u.tenant_id.clone(),
        display_name: u.display_name.clone(),
        role: u.role.as_str().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_storage::sqlite::SqliteRepository;

    async fn svc(mode: DeploymentMode) -> AuthService {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        AuthService::new(
            repo,
            AuthConfig {
                mode,
                jwt_secret: "x".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: true,
                default_plan: "free".into(),
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn single_user_mode_needs_no_token() {
        let s = svc(DeploymentMode::SingleUser).await;
        s.bootstrap_local().await.unwrap();
        s.bootstrap_local().await.unwrap();
        let p = s.authenticate(None).await.unwrap();
        assert_eq!(p.role, Role::Owner);
        assert_eq!(s.profile(&p).await.unwrap().display_name, "Local Owner");
        assert!(s.register(&reg("a@b.c")).await.is_err(), "no registration in single-user mode");
    }

    fn reg(email: &str) -> RegisterRequest {
        RegisterRequest {
            email: email.into(),
            password: "password123".into(),
            display_name: "Ada".into(),
            tenant_name: None,
        }
    }

    #[tokio::test]
    async fn multi_tenant_register_login_and_tokens() {
        let s = svc(DeploymentMode::MultiTenant).await;
        assert!(s.authenticate(None).await.is_err());
        let r = s.register(&reg("ada@example.com")).await.unwrap();
        let p = s.authenticate(Some(&r.access_token)).await.unwrap();
        assert_eq!(p.tenant_id, r.user.tenant_id);

        let login = s.login(&LoginRequest { email: "ADA@example.com".into(), password: "password123".into() }).await;
        assert!(login.is_ok());
        let bad = s.login(&LoginRequest { email: "ada@example.com".into(), password: "nope-nope".into() }).await;
        assert!(matches!(bad, Err(CoreError::Unauthorized(_))));

        let t = s.create_api_token(&p, "agent", vec!["content:read".into()], Some(30)).await.unwrap();
        let tp = s.authenticate(Some(&t.plaintext)).await.unwrap();
        assert!(tp.can(Permission::ContentRead));
        assert!(!tp.can(Permission::ContentWrite));
        assert!(s.create_api_token(&tp, "x", vec![], None).await.is_err(), "scoped token lacks token:manage");
        assert!(s.authenticate(Some("ltk_bogus")).await.is_err());

        let refreshed = s.refresh(&p).await.unwrap();
        assert_eq!(refreshed.user.user_id, r.user.user_id);
        assert_eq!(refreshed.expires_in, 3600);
        let rp = s.authenticate(Some(&refreshed.access_token)).await.unwrap();
        assert_eq!(rp.user_id, p.user_id);
    }
}

#[cfg(test)]
mod credential_boundary_tests {
    use super::*;
    use memoswish_storage::sqlite::SqliteRepository;

    #[tokio::test]
    async fn restricted_credentials_cannot_refresh_or_expand_scopes() {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let auth = AuthService::new(
            repo,
            AuthConfig {
                mode: DeploymentMode::SingleUser,
                jwt_secret: "x".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: false,
                default_plan: "free".into(),
            },
        )
        .unwrap();
        auth.bootstrap_local().await.unwrap();
        let owner = auth.authenticate(None).await.unwrap();
        assert!(auth.refresh(&owner).await.is_ok());
        let token = auth
            .create_api_token(&owner, "scoped", vec!["content:read".into(), "token:manage".into()], None)
            .await
            .unwrap();
        let p = auth.authenticate(Some(&token.plaintext)).await.unwrap();
        assert!(matches!(auth.refresh(&p).await, Err(CoreError::Forbidden(_))));
        assert!(matches!(
            auth.create_api_token(&p, "expanded", vec!["content:write".into()], None).await,
            Err(CoreError::Forbidden(_))
        ));
        assert!(auth.create_api_token(&p, "narrow", vec!["content:read".into()], None).await.is_ok());
        for via in ["api_token", "mcp_oauth", "stdio", "cli", "unknown"] {
            let mut p = owner.clone();
            p.via = via.into();
            assert!(matches!(auth.refresh(&p).await, Err(CoreError::Forbidden(_))), "{via}");
        }
        let wildcard = auth.create_api_token(&owner, "wildcard", vec!["*".into()], None).await.unwrap();
        let wildcard = auth.authenticate(Some(&wildcard.plaintext)).await.unwrap();
        assert!(auth.create_api_token(&wildcard, "narrower", vec!["content:read".into()], None).await.is_ok());
        assert!(auth.refresh(&wildcard).await.is_err());
        let mut p = owner;
        p.via = "jwt".into();
        p.scopes = Some(vec!["content:read".into()]);
        assert!(auth.refresh(&p).await.is_err());
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use memoswish_core::identity::{FederatedIdentity, IdentityRepo};
    use memoswish_core::repo::{AuthRepo, MembershipRepo};
    use memoswish_storage::sqlite::SqliteRepository;

    #[tokio::test]
    async fn account_sessions_survive_member_removal_and_old_credentials_never_rejoin() {
        let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let service = AuthService::new(
            repo.clone(),
            AuthConfig {
                mode: DeploymentMode::MultiTenant,
                jwt_secret: "x".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: true,
                default_plan: "free".into(),
            },
        )
        .unwrap();
        let req = LoginRequest { email: "ada@example.com".into(), password: "password123".into() };
        let registered = service
            .register(&RegisterRequest {
                email: req.email.clone(),
                password: req.password.clone(),
                display_name: "Ada".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        let a = service.authenticate(Some(&registered.access_token)).await.unwrap();
        let api = service.create_api_token(&a, "old", vec!["*".into()], None).await.unwrap();
        let tenant = TenantRecord { id: new_id(), name: "B".into(), plan: "free".into(), created_at: Utc::now() };
        repo.upsert_tenant(&tenant).await.unwrap();
        repo.membership_join(&tenant.id, &a.user_id, Role::Learner).await.unwrap();
        let account = service.login_account(&req).await.unwrap();
        let ap = service.authenticate_account(&account.access_token).await.unwrap();
        let b = service.select_workspace(&ap, &tenant.id).await.unwrap();
        assert_eq!(service.authenticate(Some(&b.access_token)).await.unwrap().role, Role::Learner);
        assert!(service.authenticate(Some(&account.access_token)).await.is_err());
        assert!(service.authenticate_account(&registered.access_token).await.is_err());
        assert!(service.authenticate_account(&api.plaintext).await.is_err());
        assert!(service.authenticate_account("lto_at_delegated").await.is_err());
        assert!(service.authenticate_account("lto_rt_delegated").await.is_err());
        repo.membership_remove(&a.tenant_id, &a.user_id).await.unwrap();
        assert!(service.authenticate(Some(&registered.access_token)).await.is_err());
        assert!(service.authenticate(Some(&api.plaintext)).await.is_err());
        assert!(service.refresh(&a).await.is_err());
        assert!(service.authenticate(Some(&b.access_token)).await.is_ok());
        assert!(service.authenticate_account(&account.access_token).await.is_ok());
        repo.membership_join(&a.tenant_id, &a.user_id, Role::Owner).await.unwrap();
        assert!(service.authenticate(Some(&registered.access_token)).await.is_err());
        assert!(service.authenticate(Some(&api.plaintext)).await.is_err());
        assert!(service.refresh(&a).await.is_err());
        assert!(service.create_api_token(&a, "stale", vec![], None).await.is_err());
        let fresh = service.select_workspace(&ap, &a.tenant_id).await.unwrap();
        assert_eq!(service.authenticate(Some(&fresh.access_token)).await.unwrap().membership_generation, Some(1));
        repo.membership_remove(&a.tenant_id, &a.user_id).await.unwrap();
        repo.membership_remove(&tenant.id, &a.user_id).await.unwrap();
        let zero = service.login_account(&req).await.unwrap();
        assert_eq!(zero.account.user_id, a.user_id);
        assert!(service.login(&req).await.is_err());
        let p = service.authenticate_account(&zero.access_token).await.unwrap();
        assert!(service.account_response(&p.user_id, p.generation).await.is_ok());
        assert!(service.select_workspace(&p, &a.tenant_id).await.is_err());
        assert_eq!(repo.account_export_empty(&p.user_id, p.generation).await.unwrap().account.user_id, p.user_id);
        let job = repo.account_close_empty(&p.user_id, p.generation).await.unwrap();
        assert!(job.tenant_id.is_none());
        assert!(!job.purge_assets);
        assert!(service.authenticate_account(&zero.access_token).await.is_err());
    }

    #[tokio::test]
    async fn upstream_security_event_revokes_account_and_all_memberships() {
        let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let service = AuthService::new(
            repo.clone(),
            AuthConfig {
                mode: DeploymentMode::MultiTenant,
                jwt_secret: "x".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: true,
                default_plan: "free".into(),
            },
        )
        .unwrap();
        let req = LoginRequest { email: "security@example.com".into(), password: "password123".into() };
        let initial = service
            .register(&RegisterRequest {
                email: req.email.clone(),
                password: req.password.clone(),
                display_name: "Security".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        let a = service.authenticate(Some(&initial.access_token)).await.unwrap();
        let tenant = TenantRecord { id: new_id(), name: "B".into(), plan: "free".into(), created_at: Utc::now() };
        repo.upsert_tenant(&tenant).await.unwrap();
        repo.membership_join(&tenant.id, &a.user_id, Role::Owner).await.unwrap();
        let account = service.login_account(&req).await.unwrap();
        let ap = service.authenticate_account(&account.access_token).await.unwrap();
        let b = service.select_workspace(&ap, &tenant.id).await.unwrap();
        let bp = service.authenticate(Some(&b.access_token)).await.unwrap();
        let at = service.create_api_token(&a, "A", vec![], None).await.unwrap();
        let bt = service.create_api_token(&bp, "B", vec![], None).await.unwrap();
        let identity = FederatedIdentity {
            client_id: "client".into(),
            issuer: "https://issuer.example".into(),
            subject: "subject".into(),
            provider: "test".into(),
            tenant_id: a.tenant_id.clone(),
            user_id: a.user_id.clone(),
            email: None,
            email_verified: false,
            display_name: None,
            created_at: 1,
            authenticated_at: 1,
        };
        repo.identity_resolve(
            &identity,
            None,
            true,
            None,
            Some(CredentialGenerations { account: 0, membership: 0 }),
            None,
        )
        .await
        .unwrap();
        repo.identity_event(&identity.issuer, &identity.subject, "event", "consent-revoked", 2, 2).await.unwrap();
        for token in [&initial.access_token, &b.access_token, &at.plaintext, &bt.plaintext] {
            assert!(service.authenticate(Some(token)).await.is_err());
        }
        assert!(service.authenticate_account(&account.access_token).await.is_err());
        assert!(service.select_workspace(&ap, &tenant.id).await.is_err());
        assert!(service.refresh(&a).await.is_err());
        assert_eq!(repo.account_generation(&a.user_id).await.unwrap(), 1);
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("mode", &self.mode)
            .field("jwt_secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "mcp-oauth"))]
mod import_evidence_tests {
    use super::*;
    #[tokio::test]
    async fn import_provenance_preserves_distinct_token_digest_domains() {
        let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
        let auth = AuthService::new(
            repo,
            AuthConfig {
                mode: DeploymentMode::SingleUser,
                jwt_secret: "x".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: false,
                default_plan: "self_hosted".into(),
            },
        )
        .unwrap();
        let mut p = Principal::local_owner("api_token");
        let api = auth.import_credential(&p, Some("IMPORT_SECRET_SENTINEL")).unwrap();
        p.via = "mcp_oauth".into();
        let oauth = auth.import_credential(&p, Some("IMPORT_SECRET_SENTINEL")).unwrap();
        assert_eq!(api.token_hash, Some(hash_api_token("IMPORT_SECRET_SENTINEL")));
        assert_eq!(oauth.token_hash, Some(crate::flow::digest("IMPORT_SECRET_SENTINEL")));
        assert_ne!(api.token_hash, oauth.token_hash);
        assert!(auth.import_credential(&p, None).is_err());
        p.session_access_hash = oauth.token_hash.as_ref().map(|h| format!("oauth:{h}"));
        assert_eq!(auth.import_credential(&p, None).unwrap().token_hash, oauth.token_hash);
        p.via = "api_token".into();
        assert!(auth.import_credential(&p, None).is_err());
        p.session_access_hash = api.token_hash.as_ref().map(|h| format!("api:{h}"));
        assert_eq!(auth.import_credential(&p, None).unwrap().token_hash, api.token_hash);
        p.via = "jwt".into();
        p.legacy_issued_at = Some(1);
        p.session_access_hash = Some("jwt:2000000000".into());
        assert_eq!(auth.import_credential(&p, None).unwrap().expires_at, Some(2000000000));
        let auth = auth
            .with_session_config(crate::sessions::SessionConfig {
                legacy_verify_until: Some(1900000000),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(auth.import_credential(&p, None).unwrap().expires_at, Some(1900000000));
    }
}

/// 邮箱长度先限界，再按注册规则规范化，未知账户使用相同键。
pub fn normalized_email(email: &str) -> CoreResult<String> {
    if email.len() > 1024 {
        return Err(CoreError::invalid("email input too large"));
    }
    let email = email.trim().to_lowercase();
    if email.len() > 254 {
        return Err(CoreError::invalid("email input too large"));
    }
    Ok(email)
}
