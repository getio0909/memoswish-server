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
 FOREIGN KEY(tenant_id,asset_id) REFERENCES asset_records(tenant_id,id) ON DELETE RESTRICT
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
ALTER TABLE asset_upload_intents ADD FOREIGN KEY(tenant_id,id,published_attempt) REFERENCES asset_upload_attempts(tenant_id,intent_id,id) ON DELETE RESTRICT;
CREATE FUNCTION guard_asset_reference() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM id FROM tenants WHERE id=NEW.tenant_id FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) THEN RAISE EXCEPTION 'tenant missing or erased'; END IF;
 PERFORM user_id FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id AND generation=NEW.requester_generation FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'requester membership missing'; END IF;
 PERFORM user_id FROM account_auth_epochs WHERE user_id=NEW.user_id AND generation=NEW.account_generation FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'requester account revoked'; END IF;
 IF NOT EXISTS(SELECT 1 FROM asset_upload_intents WHERE tenant_id=NEW.tenant_id AND asset_id=NEW.asset_id AND published_attempt IS NOT NULL) THEN RAISE EXCEPTION 'asset is unpublished'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER asset_reference_guard BEFORE INSERT OR UPDATE ON asset_references FOR EACH ROW EXECUTE FUNCTION guard_asset_reference();
CREATE FUNCTION immutable_asset_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'asset identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER asset_record_immutable BEFORE UPDATE ON asset_records FOR EACH ROW EXECUTE FUNCTION immutable_asset_record();
CREATE FUNCTION immutable_upload_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.tenant_id,NEW.id,NEW.intent_id,NEW.store_id,NEW.object_key,NEW.claim_token) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.intent_id,OLD.store_id,OLD.object_key,OLD.claim_token) THEN RAISE EXCEPTION 'upload identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER upload_identity_immutable BEFORE UPDATE ON asset_upload_attempts FOR EACH ROW EXECUTE FUNCTION immutable_upload_identity();
CREATE FUNCTION immutable_upload_intent_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.tenant_id,NEW.id,NEW.asset_id,NEW.account_generation) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.asset_id,OLD.account_generation) OR (OLD.published_attempt IS NOT NULL AND NEW.published_attempt IS DISTINCT FROM OLD.published_attempt) THEN RAISE EXCEPTION 'upload intent identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER upload_intent_identity_immutable BEFORE UPDATE ON asset_upload_intents FOR EACH ROW EXECUTE FUNCTION immutable_upload_intent_identity();
