//! Memoswish 认证与权限：
//!
//! - 单用户自托管模式：无需登录，所有请求映射为本地所有者（`Principal::local_owner`）。
//! - 多租户模式：JWT（App 登录）+ API Token（`ltk_` 前缀，供 AI Agent / MCP 使用，可限定 scope）。
//! - MCP OAuth：独立能力下的浏览器同意、受众绑定令牌与 refresh 家族。
//! - 配额：`QuotaPolicy` trait；自托管为 `Unlimited`，商业版为 `PlanQuota`（`commercial-quota` 特性）。

#[cfg(any(feature = "mcp-oauth", feature = "oidc"))]
mod flow;
mod lifecycle;
#[cfg(feature = "mcp-oauth")]
pub mod oauth;
pub mod oauth_config;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod oidc_config;
pub mod password;
pub mod quota;
pub mod ratelimit;
pub mod service;
pub mod token;

pub use quota::{Metric, QuotaPolicy, Unlimited, UsageMetricEntry, UsageSnapshot};
pub use ratelimit::RateLimiter;
pub use service::{AuthConfig, AuthService, CreatedToken};

pub mod sessions;

#[cfg(feature = "oidc")]
pub mod keys;

pub mod privacy;

pub mod password_lifecycle;

mod access;
