-- 合成请求、provider 证据和字节暂存独立于业务父对象，唯一调度权仍属于 background_jobs。
CREATE TABLE tts_syntheses (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, work TEXT NOT NULL CHECK(work::jsonb IS NOT NULL),
 upload_id TEXT, metadata TEXT CHECK(metadata IS NULL OR metadata::jsonb IS NOT NULL), audio BYTEA,
 legacy BIGINT NOT NULL DEFAULT 0 CHECK(legacy IN (0,1)),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,upload_id),
 FOREIGN KEY(tenant_id,id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,upload_id) REFERENCES asset_upload_intents(tenant_id,id) ON DELETE RESTRICT
);
CREATE TABLE tts_requesters (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, synthesis_id TEXT NOT NULL,
 user_id TEXT NOT NULL, account_generation BIGINT NOT NULL, membership_generation BIGINT NOT NULL,
 session_access_hash TEXT,
 content_permission BIGINT NOT NULL CHECK(content_permission IN (0,1)),
 card_id TEXT, revision BIGINT,
 outcome TEXT NOT NULL DEFAULT 'pending' CHECK(outcome IN ('pending','published','attached','conflict','not_found','requester_revoked','failed')),
 PRIMARY KEY(tenant_id,id),
 CHECK((card_id IS NULL AND revision IS NULL) OR (card_id IS NOT NULL AND revision>0)),
 FOREIGN KEY(tenant_id,synthesis_id) REFERENCES tts_syntheses(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,user_id,membership_generation) REFERENCES membership_generations(tenant_id,user_id,generation) ON DELETE RESTRICT
);
CREATE TABLE tts_provider_attempts (
 tenant_id TEXT NOT NULL, synthesis_id TEXT NOT NULL, claim_token TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('uncertain','returned')),
 PRIMARY KEY(tenant_id,synthesis_id,claim_token),
 FOREIGN KEY(tenant_id,synthesis_id) REFERENCES tts_syntheses(tenant_id,id) ON DELETE RESTRICT
);
CREATE INDEX tts_requesters_synthesis ON tts_requesters(tenant_id,synthesis_id,outcome);
