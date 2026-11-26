-- 持久输入与回执不级联依附于业务实体，删除后仍能发现外部责任。
CREATE TABLE content_imports (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL, authority_id TEXT NOT NULL, authority TEXT NOT NULL,
 work TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'pending' CHECK(outcome IN ('pending','committed','failed')),
 result TEXT,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT
);
CREATE TABLE import_uploads (
 tenant_id TEXT NOT NULL, import_id TEXT NOT NULL, ordinal BIGINT NOT NULL,
 intent_id TEXT NOT NULL, source_key TEXT NOT NULL, selected_attempt TEXT,
 PRIMARY KEY(tenant_id,import_id,ordinal), UNIQUE(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,import_id) REFERENCES content_imports(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,intent_id) REFERENCES asset_upload_intents(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,intent_id,selected_attempt) REFERENCES asset_upload_attempts(tenant_id,intent_id,id) ON DELETE RESTRICT
);
CREATE TABLE import_followups (
 tenant_id TEXT NOT NULL, import_id TEXT NOT NULL, card_id TEXT NOT NULL, revision BIGINT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('pending','running','succeeded','failed','interrupted')),
 PRIMARY KEY(tenant_id,import_id,card_id),
 FOREIGN KEY(tenant_id,import_id) REFERENCES content_imports(tenant_id,id) ON DELETE RESTRICT
);
CREATE INDEX imports_pending ON content_imports(outcome,tenant_id,id);
CREATE INDEX import_held_usage ON quota_operations(tenant_id,metric,period,state);
