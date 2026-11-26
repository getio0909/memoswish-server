-- 无法与权威 SQL 行对应的旧快照保留审计数据，但撤销其授权。
UPDATE oauth_grants AS g SET revoked=1 WHERE json_extract(g.metadata,'$.id') IS NOT g.id OR json_extract(g.metadata,'$.tenant_id') IS NOT g.tenant_id OR json_extract(g.metadata,'$.user_id') IS NOT g.user_id OR json_extract(g.metadata,'$.client_id') IS NOT g.client_id OR EXISTS(SELECT 1 FROM oauth_authorization_codes c WHERE c.grant_id=g.id AND (json_extract(c.body,'$.grant.id') IS NOT g.id OR json_extract(c.body,'$.grant.tenant_id') IS NOT g.tenant_id OR json_extract(c.body,'$.grant.user_id') IS NOT g.user_id OR json_extract(c.body,'$.grant.client_id') IS NOT g.client_id)) OR EXISTS(SELECT 1 FROM oauth_tokens c WHERE c.grant_id=g.id AND (json_extract(c.body,'$.grant.id') IS NOT g.id OR json_extract(c.body,'$.grant.tenant_id') IS NOT g.tenant_id OR json_extract(c.body,'$.grant.user_id') IS NOT g.user_id OR json_extract(c.body,'$.grant.client_id') IS NOT g.client_id));
-- 凭据世代由迁移时的权威账户及成员记录回填，不改消费、撤销或有效期。
ALTER TABLE api_tokens ADD COLUMN account_generation BIGINT NOT NULL DEFAULT 0 CHECK(account_generation>=0);
ALTER TABLE api_tokens ADD COLUMN membership_generation BIGINT NOT NULL DEFAULT 0 CHECK(membership_generation>=0);
UPDATE api_tokens SET account_generation=(SELECT generation FROM account_auth_epochs WHERE user_id=api_tokens.user_id), membership_generation=(SELECT generation FROM tenant_memberships WHERE tenant_id=api_tokens.tenant_id AND user_id=api_tokens.user_id);
UPDATE oauth_grants SET metadata=json_set(metadata,'$.generations',json_object('account',(SELECT generation FROM account_auth_epochs WHERE user_id=oauth_grants.user_id),'membership',(SELECT generation FROM tenant_memberships WHERE tenant_id=oauth_grants.tenant_id AND user_id=oauth_grants.user_id)));
UPDATE oauth_authorization_codes SET body=json_set(body,'$.grant.generations',json((SELECT json_extract(metadata,'$.generations') FROM oauth_grants WHERE id=oauth_authorization_codes.grant_id)));
UPDATE oauth_tokens SET body=json_set(body,'$.grant.generations',json((SELECT json_extract(metadata,'$.generations') FROM oauth_grants WHERE id=oauth_tokens.grant_id)));
UPDATE auth_browser_sessions SET body=json_set(body,'$.generations',CASE WHEN user_id IS NULL THEN NULL ELSE json_object('account',(SELECT generation FROM account_auth_epochs WHERE user_id=auth_browser_sessions.user_id),'membership',(SELECT generation FROM tenant_memberships WHERE tenant_id=auth_browser_sessions.tenant_id AND user_id=auth_browser_sessions.user_id)) END);
-- 登录续接属于账户，移除成员不会删除账户登录状态。
CREATE TABLE s4_new_oidc_attempts (
 id TEXT PRIMARY KEY, state_hash TEXT NOT NULL UNIQUE, launch_hash TEXT NOT NULL,
 browser_hash TEXT NOT NULL, provider TEXT NOT NULL, phase BIGINT NOT NULL DEFAULT 0,
 expires_at BIGINT NOT NULL, body TEXT NOT NULL,
 tenant_id TEXT, user_id TEXT,
 sequence BIGINT NOT NULL DEFAULT 0,
 identity_issuer TEXT,
 identity_subject TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO s4_new_oidc_attempts SELECT * FROM oidc_attempts;
DROP TABLE oidc_attempts;
ALTER TABLE s4_new_oidc_attempts RENAME TO oidc_attempts;
-- 登录续接属于账户，移除成员不会删除账户登录状态。
CREATE TABLE s4_new_oidc_handoffs (
 hash TEXT PRIMARY KEY, provider TEXT NOT NULL, challenge TEXT NOT NULL,
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL, body TEXT NOT NULL,
 attempt_id TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO s4_new_oidc_handoffs SELECT * FROM oidc_handoffs;
DROP TABLE oidc_handoffs;
ALTER TABLE s4_new_oidc_handoffs RENAME TO oidc_handoffs;
-- 登录续接属于账户，移除成员不会删除账户登录状态。
CREATE TABLE s4_new_recent_authentication (
 hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO s4_new_recent_authentication SELECT * FROM recent_authentication;
DROP TABLE recent_authentication;
ALTER TABLE s4_new_recent_authentication RENAME TO recent_authentication;
CREATE INDEX oidc_attempt_expiry ON oidc_attempts(expires_at);
CREATE INDEX recent_auth_expiry ON recent_authentication(expires_at);
CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs(expires_at);
CREATE INDEX oidc_attempt_identity ON oidc_attempts(identity_issuer,identity_subject);
CREATE INDEX oidc_handoff_attempt ON oidc_handoffs(attempt_id);
-- 升级使未完成 OIDC 流程失效，避免把旧单世代解释成账户世代。
DELETE FROM oidc_handoffs;
DELETE FROM oidc_attempts;
DELETE FROM recent_authentication;
ALTER TABLE oidc_attempts ADD COLUMN membership_generation BIGINT CHECK(membership_generation>=0);
