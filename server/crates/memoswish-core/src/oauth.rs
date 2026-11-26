//! OAuth 持久化契约。全局认证索引只用于解析凭据归属，业务写操作显式校验租户。

use crate::CoreResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthClient {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub auth_method: String,
    pub secret_hash: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// 匿名会话在密码认证后旋转；认证方式字段可供后续 OIDC 接入。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub hash: String,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub generations: Option<crate::principal::CredentialGenerations>,
    pub auth_time: i64,
    pub auth_method: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub id: String,
    pub browser_hash: String,
    pub csrf_hash: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub challenge: String,
    pub state: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthGrant {
    pub generations: crate::principal::CredentialGenerations,
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub client_id: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub hash: String,
    pub grant: OAuthGrant,
    pub redirect_uri: String,
    pub challenge: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub hash: String,
    pub grant: OAuthGrant,
    pub scopes: Vec<String>,
    pub kind: String,
    pub expires_at: i64,
}

/// 认证前的全局索引是租户参数规则的窄例外；查询结果不能绕过后续租户校验。
#[async_trait]
pub trait OAuthIndex: Send + Sync {
    async fn oauth_client(&self, client_id: &str) -> CoreResult<Option<OAuthClient>>;
    async fn oauth_register(&self, client: &OAuthClient) -> CoreResult<()>;
    async fn oauth_browser(&self, hash: &str) -> CoreResult<Option<BrowserSession>>;
    async fn oauth_request(&self, id: &str) -> CoreResult<Option<AuthorizationRequest>>;
    async fn oauth_begin(&self, session: &BrowserSession, request: &AuthorizationRequest) -> CoreResult<()>;
    async fn oauth_code(&self, hash: &str) -> CoreResult<Option<AuthorizationCode>>;
    async fn oauth_token(&self, hash: &str) -> CoreResult<Option<OAuthToken>>;
    /// 维护入口：删除过期授权时级联清除其凭据，保留有效家族的重用检测记录。
    async fn oauth_cleanup(&self, now: i64) -> CoreResult<()>;
}

#[async_trait]
pub trait OAuthRepo: OAuthIndex {
    async fn oauth_login(
        &self,
        tenant_id: &str,
        request: &AuthorizationRequest,
        session: &BrowserSession,
        now: i64,
    ) -> CoreResult<bool>;
    async fn oauth_consent(
        &self,
        tenant_id: &str,
        request: &AuthorizationRequest,
        code: Option<&AuthorizationCode>,
        now: i64,
    ) -> CoreResult<bool>;
    /// 锁定授权家族后消费授权码，成功时原子插入全部令牌。
    async fn oauth_redeem(
        &self,
        tenant_id: &str,
        code: &AuthorizationCode,
        tokens: &[OAuthToken],
        now: i64,
    ) -> CoreResult<bool>;
    /// 锁定家族，消费父令牌；重用时提交家族撤销而不创建后继。
    async fn oauth_rotate(
        &self,
        tenant_id: &str,
        parent: &OAuthToken,
        tokens: &[OAuthToken],
        now: i64,
    ) -> CoreResult<bool>;
    async fn oauth_revoke(&self, tenant_id: &str, grant_id: &str) -> CoreResult<()>;
}
