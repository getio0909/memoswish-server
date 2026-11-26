//! 本地口令生命周期；凭据只在请求中传递，响应不包含挑战或投递详情。
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordVerificationRequest {
    pub email: String,
    pub password: String,
}
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordEmailRequest {
    pub email: String,
}
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordChallengeRequest {
    pub email: String,
    pub token: String,
}
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordResetRequest {
    pub email: String,
    pub token: String,
    pub new_password: String,
}
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordRequestAccepted {
    pub accepted: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordStatus {
    pub password_enabled: bool,
    pub email_verified: bool,
    pub mail_available: bool,
}

// 请求的 Debug 永不暴露密码、邮箱和 bearer 证明。
macro_rules! redacted_debug {
    ($($t:ty),+ $(,)?) => {$(impl std::fmt::Debug for $t {
        fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
            f.write_str(concat!(stringify!($t), " { [REDACTED] }"))
        }
    })+};
}
redacted_debug!(
    PasswordVerificationRequest,
    PasswordEmailRequest,
    PasswordChallengeRequest,
    PasswordResetRequest,
    PasswordChangeRequest
);
