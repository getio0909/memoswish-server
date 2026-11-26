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
CREATE TRIGGER erased_decks_insert BEFORE INSERT ON decks WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_decks_update BEFORE UPDATE ON decks WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_cards_insert BEFORE INSERT ON cards WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_cards_update BEFORE UPDATE ON cards WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_bgm_tracks_insert BEFORE INSERT ON bgm_tracks WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_bgm_tracks_update BEFORE UPDATE ON bgm_tracks WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_usage_counters_insert BEFORE INSERT ON usage_counters WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_usage_counters_update BEFORE UPDATE ON usage_counters WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_memory_states_insert BEFORE INSERT ON memory_states WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_memory_states_update BEFORE UPDATE ON memory_states WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_feedback_events_insert BEFORE INSERT ON feedback_events WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_feedback_events_update BEFORE UPDATE ON feedback_events WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_feed_sessions_insert BEFORE INSERT ON feed_sessions WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_feed_sessions_update BEFORE UPDATE ON feed_sessions WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_users_insert BEFORE INSERT ON users WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_users_update BEFORE UPDATE ON users WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_api_tokens_insert BEFORE INSERT ON api_tokens WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_api_tokens_update BEFORE UPDATE ON api_tokens WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;

ALTER TABLE oauth_grants ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}';
UPDATE oauth_grants SET metadata=COALESCE((SELECT json_extract(body,'$.grant') FROM oauth_tokens WHERE grant_id=oauth_grants.id LIMIT 1),(SELECT json_extract(body,'$.grant') FROM oauth_authorization_codes WHERE grant_id=oauth_grants.id LIMIT 1),'{}');
CREATE TRIGGER missing_user_memory_states_insert BEFORE INSERT ON memory_states WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_memory_states_update BEFORE UPDATE ON memory_states WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_feedback_events_insert BEFORE INSERT ON feedback_events WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_feedback_events_update BEFORE UPDATE ON feedback_events WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_feed_sessions_insert BEFORE INSERT ON feed_sessions WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_feed_sessions_update BEFORE UPDATE ON feed_sessions WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_api_tokens_insert BEFORE INSERT ON api_tokens WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
CREATE TRIGGER missing_user_api_tokens_update BEFORE UPDATE ON api_tokens WHEN EXISTS(SELECT 1 FROM erased_users WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id) BEGIN SELECT RAISE(ABORT,'user erased'); END;
