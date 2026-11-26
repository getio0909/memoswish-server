//! Memoswish MCP 网关。
//!
//! - 协议：JSON-RPC 2.0 + MCP（`initialize` / `ping` / `tools/list` / `tools/call`），协商版本见 [`protocol::SUPPORTED_VERSIONS`]。
//! - 传输：本地 Stdio（[`stdio`]）与远程 Streamable HTTP（[`http`]，可按 `Accept` 以 SSE 单事件返回）。
//! - 安全：每次调用都经过多租户认证（`AuthService`）、RBAC、配额（`QuotaPolicy`）与租户级限流。
//!
//! 通过 MCP 的 tools/list 方法查询工具清单和参数 Schema。

mod control;
pub mod http;
pub mod protocol;
pub mod server;
pub mod stdio;
pub mod tools;

pub use memoswish_application::Services;
pub use server::McpServer;

#[cfg(test)]
static APKG_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
