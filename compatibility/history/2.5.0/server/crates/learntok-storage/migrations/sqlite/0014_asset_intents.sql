-- 外部责任不级联依附于租户、账户或业务内容；历史世代永久保留。
CREATE TABLE asset_records (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL,
 mime TEXT NOT NULL CHECK(length(mime) BETWEEN 3 AND 128),
 size BIGINT NOT NULL CHECK(size BETWEEN 0 AND 67108864),
 sha256 TEXT NOT NULL CHECK(length(sha256)=64),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE asset_upload_intents (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, asset_id TEXT NOT NULL,
 account_generation BIGINT NOT NULL CHECK(account_generation>=0),
 published_attempt TEXT,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,asset_id),
 FOREIGN KEY(tenant_id,id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,asset_id) REFERENCES asset_records(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,id,published_attempt) REFERENCES asset_upload_attempts(tenant_id,intent_id,id) ON DELETE RESTRICT
);
CREATE TABLE asset_upload_attempts (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, intent_id TEXT NOT NULL,
 store_id TEXT NOT NULL CHECK(length(store_id) BETWEEN 1 AND 128),
 object_key TEXT NOT NULL CHECK(length(object_key)<=512), claim_token TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('in_flight','uploaded','uncertain','cleanup_pending','cleaned')),
 version_kind TEXT NOT NULL DEFAULT 'unknown' CHECK(version_kind IN ('unknown','unversioned','version')),
 version_id TEXT CHECK(version_id IS NULL OR length(version_id) BETWEEN 1 AND 1024),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,intent_id,id), UNIQUE(tenant_id,object_key), UNIQUE(tenant_id,intent_id,claim_token),
 CHECK((version_kind='version' AND version_id IS NOT NULL) OR (version_kind<>'version' AND version_id IS NULL)),
 CHECK(outcome NOT IN ('uploaded','cleanup_pending','cleaned') OR version_kind<>'unknown'),
 FOREIGN KEY(tenant_id,intent_id) REFERENCES asset_upload_intents(tenant_id,id) ON DELETE RESTRICT
);
CREATE INDEX asset_attempts_intent ON asset_upload_attempts(tenant_id,intent_id,id);
CREATE TABLE asset_references (
 tenant_id TEXT NOT NULL, asset_id TEXT NOT NULL,
 user_id TEXT NOT NULL, requester_generation BIGINT NOT NULL, account_generation BIGINT NOT NULL,
 owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 128),
 slot TEXT NOT NULL CHECK(length(slot) BETWEEN 1 AND 128),
 PRIMARY KEY(tenant_id,user_id,owner_id,slot),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES asset_records(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,user_id,requester_generation) REFERENCES membership_generations(tenant_id,user_id,generation) ON DELETE RESTRICT
);
CREATE INDEX asset_reference_lookup ON asset_references(tenant_id,asset_id);
-- SQLite 在表定义处添加复合回执外键；前向表引用由 SQLite 支持。
CREATE TRIGGER asset_reference_guard BEFORE INSERT ON asset_references
 WHEN NOT EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id)
 OR EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id)
 OR NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id AND generation=NEW.requester_generation)
 OR NOT EXISTS(SELECT 1 FROM account_auth_epochs WHERE user_id=NEW.user_id AND generation=NEW.account_generation)
 OR NOT EXISTS(SELECT 1 FROM asset_upload_intents WHERE tenant_id=NEW.tenant_id AND asset_id=NEW.asset_id AND published_attempt IS NOT NULL)
 BEGIN SELECT RAISE(ABORT,'asset reference admission rejected'); END;
CREATE TRIGGER asset_reference_immutable BEFORE UPDATE ON asset_references
 BEGIN SELECT RAISE(ABORT,'asset reference is immutable'); END;
CREATE TRIGGER asset_record_immutable BEFORE UPDATE ON asset_records
 WHEN NEW.tenant_id IS NOT OLD.tenant_id OR NEW.id IS NOT OLD.id OR NEW.mime IS NOT OLD.mime OR NEW.size IS NOT OLD.size OR NEW.sha256 IS NOT OLD.sha256
 BEGIN SELECT RAISE(ABORT,'asset identity is immutable'); END;
CREATE TRIGGER upload_identity_immutable BEFORE UPDATE ON asset_upload_attempts
 WHEN NEW.tenant_id IS NOT OLD.tenant_id OR NEW.id IS NOT OLD.id OR NEW.intent_id IS NOT OLD.intent_id OR NEW.store_id IS NOT OLD.store_id OR NEW.object_key IS NOT OLD.object_key OR NEW.claim_token IS NOT OLD.claim_token
 BEGIN SELECT RAISE(ABORT,'upload identity is immutable'); END;
CREATE TRIGGER upload_intent_identity_immutable BEFORE UPDATE ON asset_upload_intents
 WHEN NEW.tenant_id IS NOT OLD.tenant_id OR NEW.id IS NOT OLD.id OR NEW.asset_id IS NOT OLD.asset_id OR NEW.account_generation IS NOT OLD.account_generation OR (OLD.published_attempt IS NOT NULL AND NEW.published_attempt IS NOT OLD.published_attempt)
 BEGIN SELECT RAISE(ABORT,'upload intent identity is immutable'); END;
