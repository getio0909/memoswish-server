//! 身份主体与 RBAC 权限矩阵。

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::ids::{LOCAL_TENANT_ID, LOCAL_USER_ID};

/// 租户内角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// 租户所有者：全部权限（含计费、成员管理）。
    Owner,
    /// 管理员：内容与成员管理。
    Admin,
    /// 编辑者：可管理内容、BGM、TTS（AI Agent 的典型角色）。
    Editor,
    /// 学习者：只能刷卡与上报埋点。
    Learner,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Learner => "learner",
        }
    }

    pub fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "owner" => Ok(Role::Owner),
            "admin" => Ok(Role::Admin),
            "editor" => Ok(Role::Editor),
            "learner" => Ok(Role::Learner),
            other => Err(CoreError::invalid(format!("unknown role `{other}`"))),
        }
    }

    /// RBAC 权限矩阵（唯一定义处）。
    pub fn allows(&self, p: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Owner => true,
            Role::Admin => !matches!(p, BillingManage),
            Role::Editor => matches!(
                p,
                FeedRead
                    | FeedbackWrite
                    | ContentRead
                    | ContentWrite
                    | MediaRead
                    | MediaWrite
                    | TtsGenerate
                    | AccountExport
            ),
            Role::Learner => matches!(p, FeedRead | FeedbackWrite | ContentRead | MediaRead | AccountExport),
        }
    }
}

/// 细粒度权限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    AccountExport,
    FeedRead,
    FeedbackWrite,
    ContentRead,
    ContentWrite,
    MediaRead,
    MediaWrite,
    TtsGenerate,
    TokenManage,
    MemberManage,
    BillingManage,
}

impl Permission {
    /// 可投影到 scope 的完整权限集；实际授权仍复用角色与 scope 的交集。
    pub const ALL: [Self; 11] = [
        Self::AccountExport,
        Self::FeedRead,
        Self::FeedbackWrite,
        Self::ContentRead,
        Self::ContentWrite,
        Self::MediaRead,
        Self::MediaWrite,
        Self::TtsGenerate,
        Self::TokenManage,
        Self::MemberManage,
        Self::BillingManage,
    ];
    /// 用于 API Token scope 的字符串形式，例如 `content:write`。
    pub fn as_scope(&self) -> &'static str {
        match self {
            Permission::AccountExport => "account:export",
            Permission::FeedRead => "feed:read",
            Permission::FeedbackWrite => "feedback:write",
            Permission::ContentRead => "content:read",
            Permission::ContentWrite => "content:write",
            Permission::MediaRead => "media:read",
            Permission::MediaWrite => "media:write",
            Permission::TtsGenerate => "tts:generate",
            Permission::TokenManage => "token:manage",
            Permission::MemberManage => "member:manage",
            Permission::BillingManage => "billing:manage",
        }
    }
}

/// 已认证的调用主体（来自 JWT、API Token、MCP OAuth 或单用户模式）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub tenant_id: String,
    pub user_id: String,
    pub role: Role,
    /// API Token / MCP OAuth 的 scope 限制；`None` 表示不额外限制（JWT / 单用户）。
    pub scopes: Option<Vec<String>>,
    /// 认证方式：`single_user` | `session` | `jwt` | `api_token` | `mcp_oauth` | `stdio`。
    pub via: String,
    /// 原凭据非秘密摘要，用于持久请求在事务内重查；session 保留裸摘要，委托凭据使用 api:/oauth: 前缀，旧 JWT 使用 jwt: 到期秒数。
    #[serde(skip)]
    pub session_access_hash: Option<String>,
    /// 认证时验证的世代；后续签发不能重新读取并升级。
    #[serde(default)]
    pub auth_generation: Option<i64>,
    /// 认证时捕获的成员世代，与账户安全世代独立。
    #[serde(default)]
    pub membership_generation: Option<i64>,
    /// 原始已验证 JWT 的时间证据，续签不得读取当前时间替代。
    #[serde(default)]
    pub legacy_issued_at: Option<i64>,
}

impl Principal {
    /// 返回认证时捕获的完整世代，缺失时关闭写入准入。
    pub fn credential_generations(&self) -> CoreResult<CredentialGenerations> {
        match (self.auth_generation, self.membership_generation) {
            (Some(account), Some(membership)) if account >= 0 && membership >= 0 => {
                Ok(CredentialGenerations { account, membership })
            }
            _ => Err(CoreError::Unauthorized("credential generations are missing".into())),
        }
    }

    /// 单用户自托管模式的本地所有者。
    pub fn local_owner(via: &str) -> Self {
        Self {
            tenant_id: LOCAL_TENANT_ID.into(),
            user_id: LOCAL_USER_ID.into(),
            role: Role::Owner,
            scopes: None,
            via: via.into(),
            session_access_hash: None,
            auth_generation: Some(0),
            membership_generation: Some(0),
            legacy_issued_at: None,
        }
    }

    /// 是否拥有某权限（角色矩阵 ∩ Token scope）。
    pub fn can(&self, p: Permission) -> bool {
        if !self.role.allows(p) {
            return false;
        }
        match &self.scopes {
            None => true,
            Some(scopes) => scopes.iter().any(|s| s == "*" || s == p.as_scope()),
        }
    }

    /// 校验权限，不满足时返回 `Forbidden`。
    pub fn require(&self, p: Permission) -> CoreResult<()> {
        if self.can(p) { Ok(()) } else { Err(CoreError::Forbidden(format!("missing permission `{}`", p.as_scope()))) }
    }

    /// 本租户对象存储键前缀。
    pub fn asset_prefix(&self) -> String {
        format!("tenants/{}/", self.tenant_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbac_matrix() {
        assert!(Role::Owner.allows(Permission::BillingManage));
        assert!(!Role::Admin.allows(Permission::BillingManage));
        assert!(Role::Editor.allows(Permission::TtsGenerate));
        assert!(!Role::Editor.allows(Permission::TokenManage));
        assert!(!Role::Learner.allows(Permission::ContentWrite));
    }

    #[test]
    fn scopes_narrow_role() {
        let mut p = Principal::local_owner("api_token");
        p.scopes = Some(vec!["content:read".into()]);
        assert!(p.can(Permission::ContentRead));
        assert!(!p.can(Permission::ContentWrite));
        assert!(p.require(Permission::TtsGenerate).is_err());
    }
}

/// 只证明全局账户身份，不具备工作区权限。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPrincipal {
    pub session_id: Option<String>,
    /// 保留原始凭据身份，旋转后不能借用同族后继的权限。
    pub session_access_hash: Option<String>,
    pub legacy_issued_at: Option<i64>,
    pub user_id: String,
    pub generation: i64,
}

/// 凭据签发时捕获的双重世代，使用时不得从当前成员关系补齐。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGenerations {
    pub account: i64,
    pub membership: i64,
}
