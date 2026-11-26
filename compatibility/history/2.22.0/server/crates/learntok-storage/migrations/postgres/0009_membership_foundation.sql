-- 拒绝不能归属到旧成员的记录，避免升级静默发明权限。
CREATE TABLE foundation_legacy_check (valid INTEGER NOT NULL CHECK(valid=1));
INSERT INTO foundation_legacy_check SELECT 0 FROM api_tokens c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
INSERT INTO foundation_legacy_check SELECT 0 FROM memory_states c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
INSERT INTO foundation_legacy_check SELECT 0 FROM feedback_events c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
INSERT INTO foundation_legacy_check SELECT 0 FROM feed_sessions c WHERE NOT EXISTS(SELECT 1 FROM users u WHERE u.tenant_id=c.tenant_id AND u.id=c.user_id);
DROP TABLE foundation_legacy_check;
-- 全局身份保留 ID；成员关系是租户角色的唯一来源。
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
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(role IN ('owner','admin','editor','learner')),
 revision BIGINT NOT NULL DEFAULT 1, joined_at TIMESTAMPTZ NOT NULL,
 generation BIGINT NOT NULL DEFAULT 0 CHECK(generation>=0),
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id,generation) REFERENCES membership_generations(tenant_id,user_id,generation)
);
INSERT INTO tenant_memberships(tenant_id,user_id,role,joined_at,generation)
 SELECT u.tenant_id,u.id,u.role,u.created_at,COALESCE(e.generation,0) FROM users u
 LEFT JOIN user_auth_epochs e ON e.tenant_id=u.tenant_id AND e.user_id=u.id;
CREATE INDEX memberships_user ON tenant_memberships(user_id,tenant_id);
ALTER TABLE auth_browser_sessions DROP CONSTRAINT auth_browser_sessions_tenant_id_user_id_fkey;
ALTER TABLE auth_browser_sessions ADD FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE;
ALTER TABLE oauth_grants DROP CONSTRAINT oauth_grants_tenant_id_user_id_fkey;
ALTER TABLE oauth_grants ADD FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE;
ALTER TABLE federated_identities DROP CONSTRAINT federated_identities_tenant_id_user_id_fkey;
ALTER TABLE federated_identities ADD FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE oidc_attempts DROP CONSTRAINT oidc_attempts_tenant_id_user_id_fkey;
ALTER TABLE oidc_attempts ADD FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE;
ALTER TABLE oidc_handoffs DROP CONSTRAINT oidc_handoffs_tenant_id_user_id_fkey;
ALTER TABLE oidc_handoffs ADD FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE;
ALTER TABLE recent_authentication DROP CONSTRAINT recent_authentication_tenant_id_user_id_fkey;
ALTER TABLE recent_authentication ADD FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE;
ALTER TABLE user_auth_epochs DROP CONSTRAINT user_auth_epochs_tenant_id_user_id_fkey;
ALTER TABLE user_auth_epochs ADD FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
DROP TRIGGER erased_users ON users;
ALTER TABLE users DROP CONSTRAINT users_tenant_id_fkey;
DROP INDEX users_tenant_user;
DROP INDEX idx_users_tenant;
ALTER TABLE users RENAME COLUMN tenant_id TO default_tenant_id;
ALTER TABLE users ALTER COLUMN default_tenant_id DROP NOT NULL;
ALTER TABLE users ADD FOREIGN KEY(default_tenant_id) REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE users DROP COLUMN role;
CREATE OR REPLACE FUNCTION reject_missing_user() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM user_id FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'membership missing or erased'; END IF;
 RETURN NEW;
END $$;
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

-- 旧世代原值保留；账户撤销和成员生命周期分别有独立存储。
CREATE TABLE account_auth_epochs (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 generation BIGINT NOT NULL CHECK(generation>=0)
);
INSERT INTO account_auth_epochs SELECT u.id,COALESCE(e.generation,0) FROM users u
 LEFT JOIN user_auth_epochs e ON e.user_id=u.id;
CREATE TRIGGER erased_memberships BEFORE INSERT OR UPDATE ON tenant_memberships
 FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE FUNCTION reject_erased_membership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) THEN
  RAISE EXCEPTION 'membership erased';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER erased_membership_users BEFORE INSERT OR UPDATE ON tenant_memberships
 FOR EACH ROW EXECUTE FUNCTION reject_erased_membership();
