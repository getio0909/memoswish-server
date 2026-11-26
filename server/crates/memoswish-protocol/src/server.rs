//! 服务端能力发现与认证相关载荷。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 已关联身份的公开摘要，不包含上游凭据或内部认证状态。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LinkedIdentity {
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
}

/// 服务端部署模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// 单用户自托管：无需登录，所有请求映射为本地所有者。
    #[default]
    SingleUser,
    /// 多租户：必须携带 JWT 或 API Token。
    MultiTenant,
}

/// `GET /v1/server-info` 响应：App 在“输入 Server URL”后首先调用。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub protocol_version: String,
    pub mode: DeploymentMode,
    /// 编译期启用的特性，例如 `self-hosted`、`commercial-saas`。
    pub features: Vec<String>,
    /// 是否允许自助注册。
    pub registration_open: bool,
    /// 完整 S21b 服务端会话前置接口，旧服务端缺省为 false。
    #[serde(default)]
    pub opaque_sessions: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_lifecycle: Option<bool>,
    pub tts_engines: Vec<String>,
    #[serde(default)]
    pub oidc_providers: Vec<OidcProviderInfo>,
}

/// `POST /v1/auth/login` 请求体。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// `POST /v1/auth/register` 请求体。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: String,
    /// 新建租户名称；为空时使用 display_name。
    #[serde(default)]
    pub tenant_name: Option<String>,
}

/// 登录 / 注册成功响应。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: UserProfile,
}

/// 当前用户概要。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UserProfile {
    pub user_id: String,
    pub tenant_id: String,
    pub display_name: String,
    /// `owner` | `admin` | `editor` | `learner`。
    pub role: String,
}

/// 已配置的第三方登录能力，旧客户端可忽略。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OidcProviderInfo {
    pub id: String,
    pub name: String,
    pub native: bool,
}
/// 发起浏览器或原生事务；关联身份使用独立的已认证端点。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OidcStartRequest {
    pub return_uri: String,
    pub app_state: String,
    pub code_challenge: String,
    #[serde(default)]
    pub native_client_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OidcStartResponse {
    pub attempt_id: String,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OidcCompleteRequest {
    pub code: String,
    pub code_verifier: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OidcExchangeRequest {
    pub attempt_id: String,
    pub id_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apple_user: Option<String>,
    pub nonce: String,
    pub code_verifier: String,
}

/// 全局账户概要，不含工作区授权。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccountProfile {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
}

/// 独立账户会话，不得用于工作区 API。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccountSessionResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub account: AccountProfile,
}

/// 从账户会话显式选择现存成员关系。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkspaceSessionRequest {
    pub tenant_id: String,
}

/// 无成员账户的有界导出，身份摘要不包含上游凭据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccountExport {
    pub account: AccountProfile,
    pub identities: Vec<LinkedIdentity>,
}

/// 第一方 opaque 会话凭据；refresh 明文仅随签发响应返回。
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SessionResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub session_id: String,
    pub account: AccountProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<UserProfile>,
}

impl std::fmt::Debug for SessionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionResponse").field("session_id", &self.session_id).finish_non_exhaustive()
    }
}

/// 严格单次刷新请求，不接受 access/API/MCP/上游凭据替代。
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRefreshRequest {
    pub refresh_token: String,
}

impl std::fmt::Debug for SessionRefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionRefreshRequest { refresh_token: [REDACTED] }")
    }
}

/// 可列举的安全会话摘要，不包含凭据或摘要索引。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub provenance: String,
    pub auth_time: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub current: bool,
}

/// 已认证账户的工作区摘要，发现后仍须显式选择。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MembershipSummary {
    pub tenant_id: String,
    pub name: String,
    pub role: String,
}
