-- 无法与权威 SQL 行对应的旧快照保留审计数据，但撤销其授权。
UPDATE oauth_grants AS g SET revoked=1 WHERE g.metadata::jsonb->>'id' IS DISTINCT FROM g.id OR g.metadata::jsonb->>'tenant_id' IS DISTINCT FROM g.tenant_id OR g.metadata::jsonb->>'user_id' IS DISTINCT FROM g.user_id OR g.metadata::jsonb->>'client_id' IS DISTINCT FROM g.client_id OR EXISTS(SELECT 1 FROM oauth_authorization_codes c WHERE c.grant_id=g.id AND (c.body::jsonb->'grant'->>'id' IS DISTINCT FROM g.id OR c.body::jsonb->'grant'->>'tenant_id' IS DISTINCT FROM g.tenant_id OR c.body::jsonb->'grant'->>'user_id' IS DISTINCT FROM g.user_id OR c.body::jsonb->'grant'->>'client_id' IS DISTINCT FROM g.client_id)) OR EXISTS(SELECT 1 FROM oauth_tokens c WHERE c.grant_id=g.id AND (c.body::jsonb->'grant'->>'id' IS DISTINCT FROM g.id OR c.body::jsonb->'grant'->>'tenant_id' IS DISTINCT FROM g.tenant_id OR c.body::jsonb->'grant'->>'user_id' IS DISTINCT FROM g.user_id OR c.body::jsonb->'grant'->>'client_id' IS DISTINCT FROM g.client_id));
-- 凭据世代由迁移时的权威账户及成员记录回填，不改消费、撤销或有效期。
ALTER TABLE api_tokens ADD COLUMN account_generation BIGINT NOT NULL DEFAULT 0 CHECK(account_generation>=0);
ALTER TABLE api_tokens ADD COLUMN membership_generation BIGINT NOT NULL DEFAULT 0 CHECK(membership_generation>=0);
UPDATE api_tokens SET account_generation=(SELECT generation FROM account_auth_epochs WHERE user_id=api_tokens.user_id), membership_generation=(SELECT generation FROM tenant_memberships WHERE tenant_id=api_tokens.tenant_id AND user_id=api_tokens.user_id);
UPDATE oauth_grants g SET metadata=(metadata::jsonb || jsonb_build_object('generations',jsonb_build_object('account',a.generation,'membership',m.generation)))::text FROM account_auth_epochs a,tenant_memberships m WHERE a.user_id=g.user_id AND m.user_id=g.user_id AND m.tenant_id=g.tenant_id;
UPDATE oauth_authorization_codes t SET body=jsonb_set(body::jsonb,'{grant}',COALESCE(body::jsonb->'grant','{}'::jsonb) || jsonb_build_object('generations',g.metadata::jsonb->'generations'))::text FROM oauth_grants g WHERE g.id=t.grant_id;
UPDATE oauth_tokens t SET body=jsonb_set(body::jsonb,'{grant}',COALESCE(body::jsonb->'grant','{}'::jsonb) || jsonb_build_object('generations',g.metadata::jsonb->'generations'))::text FROM oauth_grants g WHERE g.id=t.grant_id;
UPDATE auth_browser_sessions s SET body=(body::jsonb || jsonb_build_object('generations',jsonb_build_object('account',a.generation,'membership',m.generation)))::text FROM account_auth_epochs a,tenant_memberships m WHERE a.user_id=s.user_id AND m.user_id=s.user_id AND m.tenant_id=s.tenant_id;
UPDATE auth_browser_sessions SET body=(body::jsonb || '{"generations":null}'::jsonb)::text WHERE user_id IS NULL;
ALTER TABLE oidc_attempts DROP CONSTRAINT oidc_attempts_tenant_id_user_id_fkey;
ALTER TABLE oidc_attempts ADD FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE oidc_handoffs DROP CONSTRAINT oidc_handoffs_tenant_id_user_id_fkey;
ALTER TABLE oidc_handoffs ADD FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE recent_authentication DROP CONSTRAINT recent_authentication_tenant_id_user_id_fkey;
ALTER TABLE recent_authentication ADD FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
-- 升级使未完成 OIDC 流程失效，避免把旧单世代解释成账户世代。
DELETE FROM oidc_handoffs;
DELETE FROM oidc_attempts;
DELETE FROM recent_authentication;
ALTER TABLE oidc_attempts ADD COLUMN membership_generation BIGINT CHECK(membership_generation>=0);
