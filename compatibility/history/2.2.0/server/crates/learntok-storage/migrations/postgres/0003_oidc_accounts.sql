-- 上游身份始终使用 issuer/subject，不以邮箱作为身份主键。
CREATE TABLE federated_identities (
 issuer TEXT NOT NULL, subject TEXT NOT NULL, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
 body TEXT NOT NULL, credential TEXT,
 PRIMARY KEY(issuer,subject),
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE oidc_attempts (
 id TEXT PRIMARY KEY, state_hash TEXT NOT NULL UNIQUE, launch_hash TEXT NOT NULL,
 browser_hash TEXT NOT NULL, provider TEXT NOT NULL, phase BIGINT NOT NULL DEFAULT 0,
 expires_at BIGINT NOT NULL, body TEXT NOT NULL,
 tenant_id TEXT, user_id TEXT,
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX oidc_attempt_expiry ON oidc_attempts(expires_at);
CREATE TABLE oidc_handoffs (
 hash TEXT PRIMARY KEY, provider TEXT NOT NULL, challenge TEXT NOT NULL,
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL, body TEXT NOT NULL,
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE recent_authentication (
 hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE account_erasure_jobs (id TEXT PRIMARY KEY, body TEXT NOT NULL);
-- 永久、不含个人资料的随机租户墓碑拦截在途请求的晚到写入。
CREATE TABLE erased_tenants (tenant_id TEXT PRIMARY KEY);
CREATE TABLE erased_users (tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(tenant_id,user_id));
CREATE FUNCTION reject_erased_tenant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) THEN RAISE EXCEPTION 'tenant erased'; END IF; RETURN NEW; END $$;
CREATE TRIGGER erased_decks BEFORE INSERT OR UPDATE ON decks FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_cards BEFORE INSERT OR UPDATE ON cards FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_bgm_tracks BEFORE INSERT OR UPDATE ON bgm_tracks FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_usage_counters BEFORE INSERT OR UPDATE ON usage_counters FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_memory_states BEFORE INSERT OR UPDATE ON memory_states FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_feedback_events BEFORE INSERT OR UPDATE ON feedback_events FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_feed_sessions BEFORE INSERT OR UPDATE ON feed_sessions FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_users BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE TRIGGER erased_api_tokens BEFORE INSERT OR UPDATE ON api_tokens FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();

ALTER TABLE oauth_grants ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}';
UPDATE oauth_grants SET metadata=COALESCE((SELECT (body::jsonb->'grant')::text FROM oauth_tokens WHERE grant_id=oauth_grants.id LIMIT 1),(SELECT (body::jsonb->'grant')::text FROM oauth_authorization_codes WHERE grant_id=oauth_grants.id LIMIT 1),'{}');
CREATE FUNCTION reject_missing_user() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) THEN RAISE EXCEPTION 'user erased'; END IF; RETURN NEW; END $$;
CREATE TRIGGER missing_user_memory_states BEFORE INSERT OR UPDATE ON memory_states FOR EACH ROW EXECUTE FUNCTION reject_missing_user();
CREATE TRIGGER missing_user_feedback_events BEFORE INSERT OR UPDATE ON feedback_events FOR EACH ROW EXECUTE FUNCTION reject_missing_user();
CREATE TRIGGER missing_user_feed_sessions BEFORE INSERT OR UPDATE ON feed_sessions FOR EACH ROW EXECUTE FUNCTION reject_missing_user();
CREATE TRIGGER missing_user_api_tokens BEFORE INSERT OR UPDATE ON api_tokens FOR EACH ROW EXECUTE FUNCTION reject_missing_user();
