//! 第一方账户所有权入口；API/OAuth scope 不授予账户清单权限。
use crate::{AuthService, sessions::access_hash};
use memoswish_core::{CoreResult, session::AccessKind};
use memoswish_protocol::AccessPage;
impl AuthService {
    pub async fn access_page(&self, access: &str, kind: AccessKind, after: &str, limit: u32) -> CoreResult<AccessPage> {
        self.repo.access_page(&access_hash(access)?, kind, after, limit).await
    }
    pub async fn revoke_access(
        &self,
        access: &str,
        kind: AccessKind,
        tenant: Option<&str>,
        id: &str,
    ) -> CoreResult<bool> {
        self.repo.access_revoke(&access_hash(access)?, kind, tenant, id).await
    }
}
