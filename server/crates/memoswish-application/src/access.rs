//! 账户访问查询和选择撤销的传输无关命令。
use crate::Services;
use memoswish_core::{CoreResult, session::AccessKind};
use memoswish_protocol::AccessPage;
impl Services {
    pub async fn account_access(
        &self,
        bearer: &str,
        kind: AccessKind,
        after: &str,
        limit: u32,
    ) -> CoreResult<AccessPage> {
        self.auth.access_page(bearer, kind, after, limit).await
    }
    pub async fn revoke_account_access(
        &self,
        bearer: &str,
        kind: AccessKind,
        tenant: Option<&str>,
        id: &str,
    ) -> CoreResult<bool> {
        self.auth.revoke_access(bearer, kind, tenant, id).await
    }
}
