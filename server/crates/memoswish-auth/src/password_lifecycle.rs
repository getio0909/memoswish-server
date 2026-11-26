//! 显式邮箱证明与恢复；所有昂贵口令运算复用 CP1 的有界执行器。
use crate::{AuthService, service::normalized_email};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use memoswish_core::{
    CoreError, CoreResult,
    password_lifecycle::{ChallengePurpose, PasswordMutation, PasswordSnapshot},
};
use memoswish_protocol::*;
use std::sync::Arc;

/// 复用测试屏障模式，在证明事务提交后暂停一次，不持有数据库锁。
#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct LoginProofGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    used: std::sync::atomic::AtomicBool,
}
#[cfg(feature = "test-support")]
impl LoginProofGate {
    pub async fn entered(&self) {
        self.entered.notified().await;
    }
    pub fn release(&self) {
        self.release.notify_one();
    }
    pub(crate) async fn pause(&self) {
        if !self.used.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
}

pub trait PasswordMail: Send + Sync {
    /// 实现者先取得有界容量再接管内存正文，不得持久化或回显第三方错误。
    fn deliver(&self, destination: &str, purpose: ChallengePurpose, token: String) -> CoreResult<()>;
}

fn challenge_digest(purpose: ChallengePurpose, token: &str) -> CoreResult<String> {
    if token.len() != 43 || URL_SAFE_NO_PAD.decode(token).map_or(true, |b| b.len() != 32) {
        return Err(CoreError::Unauthorized("invalid or expired password challenge".into()));
    }
    Ok(memoswish_core::ids::sha256_hex(format!("learntok-password-v1\0{}\0{token}", purpose.as_str()).as_bytes()))
}

impl AuthService {
    pub fn with_password_lifecycle(mut self, enabled: bool, mail: Option<Arc<dyn PasswordMail>>) -> Self {
        self.password_enabled = enabled;
        self.password_mail = mail;
        self
    }
    pub(crate) fn require_password_profile(&self) -> CoreResult<()> {
        if !self.password_enabled {
            return Err(CoreError::Forbidden("password authentication is disabled by explicit profile".into()));
        }
        Ok(())
    }
    pub(crate) async fn verified_password(&self, email: &str, password: &str) -> CoreResult<PasswordSnapshot> {
        self.require_password_profile()?;
        self.passwords.validate_input(password)?;
        let email = normalized_email(email)?;
        let proof = self.repo.password_snapshot(&email).await?;
        let valid = self.passwords.verify(password, proof.as_ref().map(|p| p.password_hash.as_str())).await?;
        if !valid {
            return Err(CoreError::Unauthorized("invalid email or password".into()));
        }
        let proof = proof.expect("verified account");
        self.repo.password_proof(&proof).await?;
        Ok(proof)
    }
    async fn send_password_challenge(&self, proof: &PasswordSnapshot, purpose: ChallengePurpose) -> CoreResult<()> {
        let Some(mail) = &self.password_mail else { return Ok(()) };
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| CoreError::internal("OS randomness unavailable"))?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let digest = challenge_digest(purpose, &token)?;
        self.repo.password_challenge(proof, purpose, &digest, 1800).await?;
        // 提交先于投递；拒收、超时和不确定投递均由显式重发恢复。
        if mail.deliver(&proof.email, purpose, token).is_err() {
            tracing::warn!(target: "memoswish::auth::password_lifecycle", "Password mail delivery unavailable; explicit resend required");
        }
        Ok(())
    }
    pub async fn request_password_verification(
        &self,
        r: &PasswordVerificationRequest,
    ) -> CoreResult<PasswordRequestAccepted> {
        self.passwords.validate_input(&r.password)?;
        let email = normalized_email(&r.email)?;
        // 未知、无口令及错误口令执行相同昂贵工作；不以请求结果泄露资格。
        match self.verified_password(&email, &r.password).await {
            Ok(proof) => match self.send_password_challenge(&proof, ChallengePurpose::Verify).await {
                Ok(()) | Err(CoreError::Unauthorized(_)) => {}
                Err(e) => return Err(e),
            },
            Err(CoreError::Unauthorized(_) | CoreError::Forbidden(_)) => {}
            Err(e) => return Err(e),
        }
        Ok(PasswordRequestAccepted { accepted: true })
    }
    pub async fn request_password_reset(&self, r: &PasswordEmailRequest) -> CoreResult<PasswordRequestAccepted> {
        let email = normalized_email(&r.email)?;
        if self.password_enabled
            && let Some(mail) = &self.password_mail
        {
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes).map_err(|_| CoreError::internal("OS randomness unavailable"))?;
            let token = URL_SAFE_NO_PAD.encode(bytes);
            let digest = challenge_digest(ChallengePurpose::Reset, &token)?;
            let destination = self.repo.password_reset_challenge(&email, &digest, 1800).await?;
            if let Some(destination) = destination
                && mail.deliver(&destination, ChallengePurpose::Reset, token).is_err()
            {
                tracing::warn!(target: "memoswish::auth::password_lifecycle", "Password mail delivery unavailable; explicit resend required");
            }
        }
        Ok(PasswordRequestAccepted { accepted: true })
    }
    pub async fn verify_password_email(&self, r: &PasswordChallengeRequest) -> CoreResult<()> {
        self.require_password_profile()?;
        let email = normalized_email(&r.email)?;
        self.repo
            .password_mutate(PasswordMutation::Verify {
                email: &email,
                digest: &challenge_digest(ChallengePurpose::Verify, &r.token)?,
            })
            .await
    }
    pub async fn reset_password(&self, r: &PasswordResetRequest) -> CoreResult<()> {
        self.require_password_profile()?;
        let email = normalized_email(&r.email)?;
        let digest = challenge_digest(ChallengePurpose::Reset, &r.token)?;
        let new_hash = self.passwords.hash(&r.new_password).await?;
        self.repo.password_mutate(PasswordMutation::Reset { email: &email, digest: &digest, new_hash: &new_hash }).await
    }
    pub async fn change_password(&self, access: &str, r: &PasswordChangeRequest) -> CoreResult<()> {
        let a = self.authenticate_account(access).await?;
        let account = self
            .repo
            .account_by_id(&a.user_id)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("invalid account".into()))?;
        let proof = self.verified_password(&account.email, &r.current_password).await?;
        if a.generation != proof.generation {
            return Err(CoreError::Unauthorized("account changed".into()));
        }
        let new_hash = self.passwords.hash(&r.new_password).await?;
        self.repo
            .password_mutate(PasswordMutation::Change {
                proof: &proof,
                access_hash: &crate::sessions::access_hash(access)?,
                new_hash: &new_hash,
            })
            .await
    }
    pub async fn password_status(&self, access: &str) -> CoreResult<PasswordStatus> {
        let a = self.authenticate_account(access).await?;
        let account = self
            .repo
            .account_by_id(&a.user_id)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("invalid account".into()))?;
        let p = self
            .repo
            .password_snapshot(&account.email)
            .await?
            .ok_or_else(|| CoreError::Unauthorized("invalid account".into()))?;
        // 返回之前重验原始会话，不能让晚到响应取得新账户权限。
        self.authenticate_account(access).await?;
        Ok(PasswordStatus {
            password_enabled: self.password_enabled && !p.password_hash.is_empty(),
            email_verified: p.verified,
            mail_available: self.password_mail.is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Mail(Mutex<Vec<(String, ChallengePurpose, String)>>);
    impl PasswordMail for Mail {
        fn deliver(&self, d: &str, p: ChallengePurpose, t: String) -> CoreResult<()> {
            self.0.lock().unwrap().push((d.into(), p, t));
            Ok(())
        }
    }
    struct FailedMail;
    impl PasswordMail for FailedMail {
        fn deliver(&self, _: &str, _: ChallengePurpose, _: String) -> CoreResult<()> {
            Err(CoreError::internal("synthetic-private-mail-token"))
        }
    }
    #[tokio::test]
    async fn password_lifecycle_complete_flow_and_enumeration() {
        let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
        let mail = Arc::new(Mail::default());
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
        .unwrap()
        .with_password_lifecycle(true, Some(mail.clone()));
        let pair = auth
            .register_session(&RegisterRequest {
                email: "user@test.invalid".into(),
                password: "password-old-123".into(),
                display_name: "Learner".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        let email = pair.account.email.clone();
        assert!(!auth.password_status(&pair.access_token).await.unwrap().email_verified);
        let accepted = auth.request_password_reset(&PasswordEmailRequest { email: email.clone() }).await.unwrap();
        assert_eq!(
            accepted,
            auth.request_password_reset(&PasswordEmailRequest { email: "unknown@test.invalid".into() }).await.unwrap()
        );
        assert!(mail.0.lock().unwrap().is_empty());
        for (e, p) in [("unknown@test.invalid", "password-old-123"), (email.as_str(), "password-wrong-123")] {
            assert_eq!(
                accepted,
                auth.request_password_verification(&PasswordVerificationRequest {
                    email: e.into(),
                    password: p.into()
                })
                .await
                .unwrap()
            );
        }
        assert!(mail.0.lock().unwrap().is_empty());
        let request = PasswordVerificationRequest { email: email.clone(), password: "password-old-123".into() };
        auth.request_password_verification(&request).await.unwrap();
        let old = mail.0.lock().unwrap().last().unwrap().2.clone();
        auth.request_password_verification(&request).await.unwrap();
        let token = mail.0.lock().unwrap().last().unwrap().2.clone();
        assert!(
            auth.verify_password_email(&PasswordChallengeRequest { email: email.clone(), token: old }).await.is_err()
        );
        assert!(
            auth.reset_password(&PasswordResetRequest {
                email: email.clone(),
                token: token.clone(),
                new_password: "new-password-123".into()
            })
            .await
            .is_err()
        );
        auth.verify_password_email(&PasswordChallengeRequest { email: email.clone(), token: token.clone() })
            .await
            .unwrap();
        assert!(auth.verify_password_email(&PasswordChallengeRequest { email: email.clone(), token }).await.is_err());
        assert!(auth.password_status(&pair.access_token).await.unwrap().email_verified);
        auth.request_password_reset(&PasswordEmailRequest { email: email.clone() }).await.unwrap();
        let token = mail.0.lock().unwrap().last().unwrap().2.clone();
        assert!(auth.authenticate_account(&pair.access_token).await.is_ok());
        auth.reset_password(&PasswordResetRequest {
            email: email.clone(),
            token: token.clone(),
            new_password: "new-password-123".into(),
        })
        .await
        .unwrap();
        assert!(auth.authenticate_account(&pair.access_token).await.is_err());
        assert!(auth.refresh_session(&pair.refresh_token).await.is_err());
        assert!(
            auth.login_session(&LoginRequest { email: email.clone(), password: "password-old-123".into() })
                .await
                .is_err()
        );
        let next = auth
            .login_session(&LoginRequest { email: email.clone(), password: "new-password-123".into() })
            .await
            .unwrap();
        assert!(
            auth.change_password(
                &next.access_token,
                &PasswordChangeRequest {
                    current_password: "wrong-password-123".into(),
                    new_password: "third-password-123".into()
                }
            )
            .await
            .is_err()
        );
        auth.change_password(
            &next.access_token,
            &PasswordChangeRequest {
                current_password: "new-password-123".into(),
                new_password: "third-password-123".into(),
            },
        )
        .await
        .unwrap();
        assert!(auth.authenticate_account(&next.access_token).await.is_err());
        assert!(
            auth.login_session(&LoginRequest { email: email.clone(), password: "third-password-123".into() })
                .await
                .is_ok()
        );
        let failed = auth.clone().with_password_lifecycle(true, Some(Arc::new(FailedMail)));
        assert_eq!(
            failed.request_password_reset(&PasswordEmailRequest { email: email.clone() }).await.unwrap(),
            accepted
        );
        assert!(
            !format!(
                "{:?}",
                PasswordResetRequest {
                    email: email.clone(),
                    token: "synthetic-private-mail-token".into(),
                    new_password: "sentinel-password".into()
                }
            )
            .contains("synthetic-private-mail-token")
        );
        let disabled = auth.with_password_lifecycle(false, None);
        assert!(
            disabled
                .login_session(&LoginRequest { email: email.clone(), password: "third-password-123".into() })
                .await
                .is_err()
        );
        assert_eq!(disabled.request_password_reset(&PasswordEmailRequest { email }).await.unwrap(), accepted);
    }
}
