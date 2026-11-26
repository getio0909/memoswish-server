//! 第一方凭据的独立命名/摘要域；客户端负责串行刷新及原子保存凭据对。
use crate::AuthService;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use memoswish_core::{
    CoreError, CoreResult,
    session::{SessionAccess, SessionCredential, SessionFamily},
};
use memoswish_protocol::{
    AccountProfile, LoginRequest, MembershipSummary, RegisterRequest, SessionInfo, SessionResponse,
};
use serde::{Deserialize, Serialize};

pub const ACCESS_PREFIX: &str = "lts_at_";
pub const REFRESH_PREFIX: &str = "lts_rt_";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub access_ttl_secs: i64,
    pub family_ttl_secs: i64,
    /// S22 迁移时显式写入绝对截止秒；不能在每次重启时重算。
    pub legacy_verify_until: Option<i64>,
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self { access_ttl_secs: 900, family_ttl_secs: 30 * 24 * 3600, legacy_verify_until: None }
    }
}
impl SessionConfig {
    pub fn validate(&self) -> CoreResult<()> {
        if !(1..=86400).contains(&self.access_ttl_secs)
            || !(self.access_ttl_secs..=366 * 86400).contains(&self.family_ttl_secs)
        {
            return Err(CoreError::invalid("invalid session lifetimes"));
        }
        Ok(())
    }
}

pub fn generate_encryption_key() -> CoreResult<String> {
    token("")
}
fn token(prefix: &str) -> CoreResult<String> {
    let mut b = [0; 32];
    getrandom::fill(&mut b).map_err(|_| CoreError::internal("OS randomness unavailable"))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(b)))
}
pub fn access_hash(t: &str) -> CoreResult<String> {
    hash(t, ACCESS_PREFIX, "access")
}
pub fn refresh_hash(t: &str) -> CoreResult<String> {
    hash(t, REFRESH_PREFIX, "refresh")
}
fn hash(t: &str, prefix: &str, domain: &str) -> CoreResult<String> {
    let tail = t.strip_prefix(prefix).ok_or_else(|| CoreError::Unauthorized("invalid app credential".into()))?;
    if tail.len() != 43 || URL_SAFE_NO_PAD.decode(tail).map_or(true, |b| b.len() != 32) {
        return Err(CoreError::Unauthorized("invalid app credential".into()));
    }
    Ok(memoswish_core::ids::sha256_hex(format!("learntok-session-v1\0{domain}\0{t}").as_bytes()))
}
fn pair(f: &SessionFamily, tenant: Option<(String, i64)>, ttl: i64) -> CoreResult<(String, String, SessionCredential)> {
    let a = token(ACCESS_PREFIX)?;
    let r = token(REFRESH_PREFIX)?;
    let c = SessionCredential {
        access_hash: access_hash(&a)?,
        refresh_hash: refresh_hash(&r)?,
        assurance_hash: memoswish_core::ids::sha256_hex(a.as_bytes()),
        session_id: f.id.clone(),
        tenant_id: tenant.as_ref().map(|t| t.0.clone()),
        membership_generation: tenant.map(|t| t.1),
        expires_at: (Utc::now().timestamp() + ttl).min(f.expires_at),
    };
    Ok((a, r, c))
}

impl AuthService {
    pub fn with_session_config(mut self, config: SessionConfig) -> CoreResult<Self> {
        config.validate()?;
        self.session_config = config;
        Ok(self)
    }
    pub(crate) fn legacy_allowed(&self) -> CoreResult<()> {
        if self.session_config.legacy_verify_until.is_some_and(|t| Utc::now().timestamp() >= t) {
            return Err(CoreError::Unauthorized("legacy session expired; sign in again".into()));
        }
        Ok(())
    }
    pub async fn register_session(&self, r: &RegisterRequest) -> CoreResult<SessionResponse> {
        let (tenant, user) = self.prepare_registration(r).await?;
        let f = self.new_session_family(&user.id, 0, "password");
        let (access, refresh, c) = pair(&f, None, self.session_config.access_ttl_secs)?;
        self.repo.session_register(&tenant, &user, &f, &c).await?;
        self.session_response(access, refresh, SessionAccess { family: f, credential: c }).await
    }
    pub async fn logout_everywhere(&self, access: &str) -> CoreResult<()> {
        self.repo.session_revoke_all(&access_hash(access)?).await
    }
    pub async fn session_memberships(&self, access: &str) -> CoreResult<Vec<MembershipSummary>> {
        self.repo.session_memberships(&access_hash(access)?).await
    }
    fn new_session_family(&self, user: &str, generation: i64, provenance: &str) -> SessionFamily {
        let now = Utc::now().timestamp();
        SessionFamily {
            id: memoswish_core::ids::new_id(),
            user_id: user.into(),
            generation,
            provenance: provenance.into(),
            auth_time: now,
            expires_at: now + self.session_config.family_ttl_secs,
            revoked: false,
        }
    }
    pub async fn login_session(&self, r: &LoginRequest) -> CoreResult<SessionResponse> {
        let proof = self.verified_password(&r.email, &r.password).await?;
        self.issue_session(&proof.user_id, proof.generation, "password", None).await
    }
    pub(crate) async fn issue_session(
        &self,
        user: &str,
        generation: i64,
        provenance: &str,
        attempt: Option<&str>,
    ) -> CoreResult<SessionResponse> {
        let f = self.new_session_family(user, generation, provenance);
        let (a, r, c) = pair(&f, None, self.session_config.access_ttl_secs)?;
        self.repo.session_issue(&f, &c, attempt).await?;
        self.session_response(a, r, SessionAccess { family: f, credential: c }).await
    }
    pub async fn select_session_workspace(&self, access: &str, tenant: &str) -> CoreResult<SessionResponse> {
        let hash = access_hash(access)?;
        let a = self.repo.session_access(&hash).await?;
        let m = self
            .repo
            .memberships(&a.family.user_id)
            .await?
            .into_iter()
            .find(|m| m.tenant_id == tenant)
            .ok_or_else(|| CoreError::Unauthorized("membership no longer exists".into()))?;
        let (access, refresh, c) =
            pair(&a.family, Some((tenant.into(), m.generation)), self.session_config.access_ttl_secs)?;
        self.repo.session_select(&hash, &c).await?;
        self.session_response(access, refresh, SessionAccess { family: a.family, credential: c }).await
    }
    pub async fn refresh_session(&self, refresh: &str) -> CoreResult<SessionResponse> {
        let hash = refresh_hash(refresh)?;
        let access = token(ACCESS_PREFIX)?;
        let refresh = token(REFRESH_PREFIX)?;
        let a = self
            .repo
            .session_rotate(
                &hash,
                &access_hash(&access)?,
                &refresh_hash(&refresh)?,
                &memoswish_core::ids::sha256_hex(access.as_bytes()),
                self.session_config.access_ttl_secs,
            )
            .await?;
        self.session_response(access, refresh, a).await
    }
    async fn session_response(&self, access: String, refresh: String, a: SessionAccess) -> CoreResult<SessionResponse> {
        let u = self
            .repo
            .account_by_id(&a.family.user_id)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("account no longer exists".into()))?;
        let workspace = if let Some(t) = &a.credential.tenant_id {
            let u = self
                .repo
                .get_user(t, &a.family.user_id)
                .await?
                .ok_or_else(|| CoreError::Unauthorized("membership no longer exists".into()))?;
            Some(crate::service::profile_of(&u))
        } else {
            None
        };
        Ok(SessionResponse {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer".into(),
            expires_in: a.credential.expires_at.saturating_sub(Utc::now().timestamp()).max(0) as u64,
            session_id: a.family.id,
            account: AccountProfile { user_id: u.id, email: u.email, display_name: u.display_name },
            workspace,
        })
    }
    pub async fn list_sessions(&self, access: &str) -> CoreResult<Vec<SessionInfo>> {
        let hash = access_hash(access)?;
        let current = self.repo.session_access(&hash).await?;
        Ok(self
            .repo
            .session_list(&hash)
            .await?
            .into_iter()
            .map(|f| SessionInfo {
                current: f.id == current.family.id,
                session_id: f.id,
                provenance: f.provenance,
                auth_time: f.auth_time,
                expires_at: f.expires_at,
                revoked: f.revoked || f.generation != current.family.generation,
            })
            .collect())
    }
    pub async fn revoke_session(&self, access: &str, target: Option<&str>) -> CoreResult<bool> {
        let hash = access_hash(access)?;
        let current = self.repo.session_access(&hash).await?;
        self.repo.session_revoke(&hash, target.unwrap_or(&current.family.id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_core::repo::Repository;
    use memoswish_protocol::{DeploymentMode, RegisterRequest};
    use std::sync::Arc;
    async fn service() -> (AuthService, Arc<dyn Repository>, memoswish_protocol::AuthResponse) {
        let repo: Arc<dyn Repository> =
            Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
        let auth = AuthService::new(
            repo.clone(),
            crate::AuthConfig {
                mode: DeploymentMode::MultiTenant,
                jwt_secret: "s".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: true,
                default_plan: "free".into(),
            },
        )
        .unwrap();
        let registered = auth
            .register(&RegisterRequest {
                email: "user@test.invalid".into(),
                password: "password123!".into(),
                display_name: "User".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        (auth, repo, registered)
    }
    #[tokio::test]
    async fn lifecycle_principals_retain_original_opaque_credential() {
        use memoswish_core::lifecycle::{CloseAccount, DeleteWorkspace};
        let (auth, repo, registered) = service().await;
        let root = auth
            .login_session(&LoginRequest { email: "user@test.invalid".into(), password: "password123!".into() })
            .await
            .unwrap();
        let account = auth.authenticate_account(&root.access_token).await.unwrap();
        assert_eq!(account.session_access_hash, Some(access_hash(&root.access_token).unwrap()));
        assert_eq!(account.session_id.as_deref(), Some(root.session_id.as_str()));
        let workspace = auth.select_session_workspace(&root.access_token, &registered.user.tenant_id).await.unwrap();
        let p = auth.authenticate(Some(&workspace.access_token)).await.unwrap();
        assert_eq!(p.session_access_hash, Some(access_hash(&workspace.access_token).unwrap()));
        auth.refresh_session(&workspace.refresh_token).await.unwrap();
        assert!(matches!(
            auth.delete_workspace(&p, &DeleteWorkspace { confirmed_tenant_id: p.tenant_id.clone() }).await,
            Err(CoreError::Unauthorized(_))
        ));
        auth.refresh_session(&root.refresh_token).await.unwrap();
        assert!(matches!(
            auth.close_account(&account, &CloseAccount { confirmed_exclusive_workspaces: vec![p.tenant_id.clone()] })
                .await,
            Err(CoreError::Unauthorized(_))
        ));
        assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
        assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
        assert!(repo.account_erasure_jobs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn opaque_profiles_refresh_domains_and_zero_membership() {
        let (auth, repo, registered) = service().await;
        let login = LoginRequest { email: "user@test.invalid".into(), password: "password123!".into() };
        let s = auth.login_session(&login).await.unwrap();
        assert!(s.access_token.starts_with(ACCESS_PREFIX));
        assert!(s.refresh_token.starts_with(REFRESH_PREFIX));
        assert!(!format!("{s:?}").contains(&s.refresh_token));
        assert!(!format!("{s:?}").contains(&s.access_token));
        assert!(auth.authenticate(Some(&s.access_token)).await.is_err());
        assert!(auth.authenticate(Some(&s.refresh_token)).await.is_err());
        assert!(auth.refresh_session(&s.access_token).await.is_err());
        assert!(auth.refresh_session(&registered.access_token).await.is_err());
        let p = auth.authenticate_account(&s.access_token).await.unwrap();
        assert!(auth.select_workspace(&p, &registered.user.tenant_id).await.is_err());
        let w = auth.select_session_workspace(&s.access_token, &registered.user.tenant_id).await.unwrap();
        let wp = auth.authenticate(Some(&w.access_token)).await.unwrap();
        assert_eq!(wp.via, "session");
        assert!(auth.refresh(&wp).await.is_err());
        assert!(auth.authenticate_account(&w.access_token).await.is_err());
        let api = auth.create_api_token(&wp, "independent", vec!["*".into()], None).await.unwrap();
        assert!(auth.refresh_session(&api.plaintext).await.is_err());
        assert!(auth.refresh_session("lto_rt_foreign").await.is_err());
        let rotated = auth.refresh_session(&w.refresh_token).await.unwrap();
        assert!(auth.authenticate(Some(&w.access_token)).await.is_err());
        assert!(auth.authenticate(Some(&rotated.access_token)).await.is_ok());
        assert!(auth.refresh_session(&w.refresh_token).await.is_err());
        assert!(auth.authenticate(Some(&rotated.access_token)).await.is_err());
        assert!(auth.authenticate_account(&s.access_token).await.is_err());
        assert!(auth.authenticate(Some(&api.plaintext)).await.is_ok());
        let s = auth.login_session(&login).await.unwrap();
        repo.membership_remove(&registered.user.tenant_id, &registered.user.user_id).await.unwrap();
        let p = auth.authenticate_account(&s.access_token).await.unwrap();
        assert!(auth.refresh_session(&s.refresh_token).await.is_ok());
        assert!(repo.account_export_empty(&p.user_id, p.generation).await.is_ok());
        let cutoff = auth
            .clone()
            .with_session_config(SessionConfig { legacy_verify_until: Some(0), ..Default::default() })
            .unwrap();
        assert!(cutoff.authenticate(Some(&registered.access_token)).await.is_err());
        assert!(cutoff.account_response(&p.user_id, p.generation).await.is_err());
    }
}

#[cfg(test)]
mod prerequisite_tests {
    use super::*;
    use memoswish_protocol::{DeploymentMode, RegisterRequest};
    use std::sync::Arc;

    #[tokio::test]
    async fn registration_after_cutoff_and_captured_legacy_evidence() {
        let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
        let auth = AuthService::new(
            repo.clone(),
            crate::AuthConfig {
                mode: DeploymentMode::MultiTenant,
                jwt_secret: "s".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: true,
                default_plan: "free".into(),
            },
        )
        .unwrap();
        let request = RegisterRequest {
            email: "  Owner@Test.Invalid  ".into(),
            password: "password123!".into(),
            display_name: " Owner ".into(),
            tenant_name: None,
        };
        let pair = auth.register_session(&request).await.unwrap();
        let login = LoginRequest { email: "owner@test.invalid".into(), password: request.password.clone() };
        let account_jwt = auth.login_account(&login).await.unwrap();
        let account = auth.authenticate_account(&account_jwt.access_token).await.unwrap();
        let memberships = auth.session_memberships(&pair.access_token).await.unwrap();
        let tenant = &memberships[0].tenant_id;
        let jwt = auth.select_workspace(&account, tenant).await.unwrap();
        let principal = auth.authenticate(Some(&jwt.access_token)).await.unwrap();
        let api = auth.create_api_token(&principal, "independent", vec![], None).await.unwrap();
        auth.logout_everywhere(&pair.access_token).await.unwrap();
        assert!(auth.authenticate(Some(&jwt.access_token)).await.is_err());
        assert!(auth.authenticate_account(&account_jwt.access_token).await.is_err());
        assert!(auth.refresh(&principal).await.is_err());
        assert!(auth.refresh_account(&account).await.is_err());
        assert!(auth.select_workspace(&account, tenant).await.is_err());
        assert!(auth.authenticate(Some(&api.plaintext)).await.is_ok());
        let after = auth.login_session(&login).await.unwrap();
        assert!(auth.authenticate_account(&after.access_token).await.is_ok());
        let cutoff =
            auth.with_session_config(SessionConfig { legacy_verify_until: Some(0), ..Default::default() }).unwrap();
        assert!(cutoff.login_account(&login).await.is_err());
        let mut new_request = request.clone();
        new_request.email = "new@test.invalid".into();
        let registered = cutoff.register_session(&new_request).await.unwrap();
        assert_eq!(registered.account.email, "new@test.invalid");
        assert!(registered.workspace.is_none());
        assert!(cutoff.authenticate_account(&registered.access_token).await.is_ok());
        assert!(cutoff.register_session(&new_request).await.is_err());
        new_request.email = "invalid".into();
        assert!(cutoff.register_session(&new_request).await.is_err());
        new_request.email = "weak@test.invalid".into();
        new_request.password = "x".into();
        assert!(cutoff.register_session(&new_request).await.is_err());
    }
}
