-- 拒绝不能归属到旧成员的记录，避免升级静默发明权限。
CREATE TABLE foundation_legacy_check (valid INTEGER NOT NULL CHECK(valid=1));
INSERT INTO foundation_legacy_check SELECT 0 FROM api_tokens c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
INSERT INTO foundation_legacy_check SELECT 0 FROM memory_states c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
INSERT INTO foundation_legacy_check SELECT 0 FROM feedback_events c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
INSERT INTO foundation_legacy_check SELECT 0 FROM feed_sessions c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
DROP TABLE foundation_legacy_check;
-- 重建身份表及依赖外键；先复制全部认证状态，避免 DROP 的级联丢失历史。
CREATE TABLE global_users (
 id TEXT PRIMARY KEY, default_tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL,
 email TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL
);
INSERT INTO global_users SELECT id,tenant_id,email,display_name,password_hash,created_at FROM users;
-- 世代历史没有可删除父对象外键，后续成员生命周期可引用已结束世代。
CREATE TABLE membership_generations (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, generation BIGINT NOT NULL CHECK(generation>=0),
 PRIMARY KEY(tenant_id,user_id,generation)
);
INSERT INTO membership_generations
 SELECT u.tenant_id,u.id,COALESCE(e.generation,0) FROM users u
 LEFT JOIN user_auth_epochs e ON e.tenant_id=u.tenant_id AND e.user_id=u.id;
CREATE TABLE tenant_memberships (
 tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(role IN ('owner','admin','editor','learner')),
 revision BIGINT NOT NULL DEFAULT 1, joined_at TEXT NOT NULL,
 generation BIGINT NOT NULL DEFAULT 0 CHECK(generation>=0),
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id,generation) REFERENCES membership_generations(tenant_id,user_id,generation)
);
INSERT INTO tenant_memberships(tenant_id,user_id,role,joined_at,generation)
 SELECT u.tenant_id,u.id,u.role,u.created_at,COALESCE(e.generation,0) FROM users u
 LEFT JOIN user_auth_epochs e ON e.tenant_id=u.tenant_id AND e.user_id=u.id;
CREATE INDEX memberships_user ON tenant_memberships(user_id,tenant_id);
CREATE TABLE org_new_auth_browser_sessions (
 hash TEXT PRIMARY KEY,
    tenant_id TEXT,
    user_id TEXT,
    expires_at BIGINT NOT NULL,
    body TEXT NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
INSERT INTO org_new_auth_browser_sessions SELECT * FROM auth_browser_sessions;
CREATE TABLE org_new_oauth_authorization_requests (
 id TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL REFERENCES org_new_auth_browser_sessions(hash) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    body TEXT NOT NULL
);
INSERT INTO org_new_oauth_authorization_requests SELECT * FROM oauth_authorization_requests;
CREATE TABLE org_new_oauth_grants (
 id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    revoked BIGINT NOT NULL DEFAULT 0,
 metadata TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (tenant_id, user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE,
    UNIQUE(tenant_id, id)
);
INSERT INTO org_new_oauth_grants SELECT * FROM oauth_grants;
CREATE TABLE org_new_oauth_authorization_codes (
 hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BIGINT NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    FOREIGN KEY (tenant_id, grant_id) REFERENCES org_new_oauth_grants(tenant_id, id) ON DELETE CASCADE
);
INSERT INTO org_new_oauth_authorization_codes SELECT * FROM oauth_authorization_codes;
CREATE TABLE org_new_oauth_tokens (
 hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BIGINT NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    FOREIGN KEY (tenant_id, grant_id) REFERENCES org_new_oauth_grants(tenant_id, id) ON DELETE CASCADE
);
INSERT INTO org_new_oauth_tokens SELECT * FROM oauth_tokens;
CREATE TABLE org_new_federated_identities (
 issuer TEXT NOT NULL, subject TEXT NOT NULL, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
 body TEXT NOT NULL, credential TEXT,
 PRIMARY KEY(issuer,subject),
 FOREIGN KEY(user_id) REFERENCES global_users(id) ON DELETE CASCADE
);
INSERT INTO org_new_federated_identities SELECT * FROM federated_identities;
CREATE TABLE org_new_oidc_attempts (
 id TEXT PRIMARY KEY, state_hash TEXT NOT NULL UNIQUE, launch_hash TEXT NOT NULL,
 browser_hash TEXT NOT NULL, provider TEXT NOT NULL, phase BIGINT NOT NULL DEFAULT 0,
 expires_at BIGINT NOT NULL, body TEXT NOT NULL,
 tenant_id TEXT, user_id TEXT,
 sequence BIGINT NOT NULL DEFAULT 0,
 identity_issuer TEXT,
 identity_subject TEXT,
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
INSERT INTO org_new_oidc_attempts SELECT * FROM oidc_attempts;
CREATE TABLE org_new_oidc_handoffs (
 hash TEXT PRIMARY KEY, provider TEXT NOT NULL, challenge TEXT NOT NULL,
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL, body TEXT NOT NULL,
 attempt_id TEXT,
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
INSERT INTO org_new_oidc_handoffs SELECT * FROM oidc_handoffs;
CREATE TABLE org_new_recent_authentication (
 hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
INSERT INTO org_new_recent_authentication SELECT * FROM recent_authentication;
CREATE TABLE org_new_user_auth_epochs (
 tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,generation BIGINT NOT NULL,
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(user_id) REFERENCES global_users(id) ON DELETE CASCADE
);
INSERT INTO org_new_user_auth_epochs SELECT * FROM user_auth_epochs;
CREATE TABLE org_new_identity_status (
 issuer TEXT NOT NULL,subject TEXT NOT NULL,last_event_at BIGINT NOT NULL,
 last_event_kind TEXT NOT NULL,email_forwarding TEXT,revoked_before BIGINT NOT NULL DEFAULT 0,permanently_deleted BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(issuer,subject),
 FOREIGN KEY(issuer,subject) REFERENCES org_new_federated_identities(issuer,subject) ON DELETE CASCADE
);
INSERT INTO org_new_identity_status SELECT * FROM identity_status;
DROP TABLE oauth_tokens;
DROP TABLE oauth_authorization_codes;
DROP TABLE oauth_authorization_requests;
DROP TABLE identity_status;
DROP TABLE oauth_grants;
DROP TABLE auth_browser_sessions;
DROP TABLE federated_identities;
DROP TABLE oidc_attempts;
DROP TABLE oidc_handoffs;
DROP TABLE recent_authentication;
DROP TABLE user_auth_epochs;
DROP TABLE users;
ALTER TABLE global_users RENAME TO users;
ALTER TABLE org_new_auth_browser_sessions RENAME TO auth_browser_sessions;
ALTER TABLE org_new_oauth_authorization_requests RENAME TO oauth_authorization_requests;
ALTER TABLE org_new_oauth_grants RENAME TO oauth_grants;
ALTER TABLE org_new_oauth_authorization_codes RENAME TO oauth_authorization_codes;
ALTER TABLE org_new_oauth_tokens RENAME TO oauth_tokens;
ALTER TABLE org_new_federated_identities RENAME TO federated_identities;
ALTER TABLE org_new_oidc_attempts RENAME TO oidc_attempts;
ALTER TABLE org_new_oidc_handoffs RENAME TO oidc_handoffs;
ALTER TABLE org_new_recent_authentication RENAME TO recent_authentication;
ALTER TABLE org_new_user_auth_epochs RENAME TO user_auth_epochs;
ALTER TABLE org_new_identity_status RENAME TO identity_status;
CREATE INDEX auth_browser_expiry ON auth_browser_sessions(expires_at);
CREATE INDEX oauth_requests_expiry ON oauth_authorization_requests(expires_at);
CREATE INDEX oauth_grants_expiry ON oauth_grants(expires_at);
CREATE INDEX oauth_tokens_grant ON oauth_tokens(tenant_id, grant_id);
CREATE INDEX oidc_attempt_expiry ON oidc_attempts(expires_at);
CREATE INDEX recent_auth_expiry ON recent_authentication(expires_at);
CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs(expires_at);
CREATE INDEX oidc_attempt_identity ON oidc_attempts(identity_issuer,identity_subject);
CREATE INDEX oidc_handoff_attempt ON oidc_handoffs(attempt_id);
CREATE TABLE tenant_audit_events (
 tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 id TEXT NOT NULL, actor_id TEXT NOT NULL, credential_kind TEXT NOT NULL,
 action TEXT NOT NULL, target_id TEXT NOT NULL, before_role TEXT, after_role TEXT,
 request_id TEXT NOT NULL, occurred_at BIGINT NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX tenant_audit_order ON tenant_audit_events(tenant_id,occurred_at,id);
CREATE VIEW user_profiles AS
 SELECT u.id,m.tenant_id,u.email,u.display_name,u.password_hash,m.role,u.created_at
 FROM users u JOIN tenant_memberships m ON m.user_id=u.id;
CREATE TRIGGER require_membership_memory_states_insert BEFORE INSERT ON memory_states WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_memory_states_update BEFORE UPDATE ON memory_states WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_feedback_events_insert BEFORE INSERT ON feedback_events WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_feedback_events_update BEFORE UPDATE ON feedback_events WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_feed_sessions_insert BEFORE INSERT ON feed_sessions WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_feed_sessions_update BEFORE UPDATE ON feed_sessions WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_api_tokens_insert BEFORE INSERT ON api_tokens WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;
CREATE TRIGGER require_membership_api_tokens_update BEFORE UPDATE ON api_tokens WHEN NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'membership missing'); END;

-- 旧世代原值保留；账户撤销和成员生命周期分别有独立存储。
CREATE TABLE account_auth_epochs (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 generation BIGINT NOT NULL CHECK(generation>=0)
);
INSERT INTO account_auth_epochs SELECT u.id,COALESCE(e.generation,0) FROM users u
 LEFT JOIN user_auth_epochs e ON e.user_id=u.id;
CREATE TRIGGER erased_memberships_insert BEFORE INSERT ON tenant_memberships
 WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) OR EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id)
 BEGIN SELECT RAISE(ABORT,'membership erased'); END;
CREATE TRIGGER erased_memberships_update BEFORE UPDATE ON tenant_memberships
 WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) OR EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id)
 BEGIN SELECT RAISE(ABORT,'membership erased'); END;
-- 迁移事务中将结构检查转成约束，任何损坏都回滚本次升级。
CREATE TABLE foundation_foreign_key_check (valid INTEGER NOT NULL CHECK(valid=1));
INSERT INTO foundation_foreign_key_check SELECT 0 FROM pragma_foreign_key_check;
DROP TABLE foundation_foreign_key_check;
