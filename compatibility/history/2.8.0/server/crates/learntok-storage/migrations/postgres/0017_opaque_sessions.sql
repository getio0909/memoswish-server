-- 第一方会话族归账户；成员关系仅由各凭据捕获，不随重加入升级。
CREATE TABLE app_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL CHECK(generation >= 0),
    provenance TEXT NOT NULL CHECK(provenance IN ('password','oidc')),
    auth_time BIGINT NOT NULL,
    expires_at BIGINT NOT NULL CHECK(expires_at > auth_time),
    revoked BIGINT NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
);
CREATE INDEX app_sessions_account ON app_sessions(user_id);
-- 已消费父凭据保留到整个族过期，重启和丢响应不能绕过重放检测。
CREATE TABLE app_session_credentials (
    access_hash TEXT PRIMARY KEY,
    refresh_hash TEXT NOT NULL UNIQUE,
    assurance_hash TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES app_sessions(id) ON DELETE CASCADE,
    tenant_id TEXT,
    membership_generation BIGINT,
    expires_at BIGINT NOT NULL,
    consumed BIGINT NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)),
    CHECK((tenant_id IS NULL AND membership_generation IS NULL) OR
          (tenant_id IS NOT NULL AND membership_generation IS NOT NULL AND membership_generation >= 0))
);
CREATE INDEX app_session_credentials_assurance ON app_session_credentials(assurance_hash);
CREATE INDEX app_session_credentials_family ON app_session_credentials(session_id);
-- 待关联身份直到完成事务才成为账户登录方式。
ALTER TABLE oidc_attempts ADD COLUMN pending_link TEXT;
-- 旧流程未可靠保存原交互认证期限，升级后须重新发起，避免延长关联权限。
DELETE FROM oidc_handoffs;
DELETE FROM oidc_attempts;
