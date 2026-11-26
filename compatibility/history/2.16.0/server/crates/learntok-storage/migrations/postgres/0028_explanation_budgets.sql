-- 解释责任独立于可删除的内容父对象，金额采用整数微货币。
CREATE TABLE explanation_profiles (
 id TEXT PRIMARY KEY, policy TEXT NOT NULL, suspended BIGINT NOT NULL DEFAULT 0 CHECK(suspended IN (0,1))
);
CREATE TABLE explanation_cache_limits (
 deployment_id TEXT PRIMARY KEY, limits TEXT NOT NULL
);
CREATE TABLE explanation_accounts (
 scope TEXT NOT NULL, period TEXT NOT NULL, currency TEXT NOT NULL,
 cap BIGINT NOT NULL CHECK(cap>=0), exposure_cap BIGINT NOT NULL CHECK(exposure_cap>=0),
 committed BIGINT NOT NULL DEFAULT 0 CHECK(committed>=0), held BIGINT NOT NULL DEFAULT 0 CHECK(held>=0),
 PRIMARY KEY(scope,period)
);
CREATE TABLE explanation_operations (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL,
 card_id TEXT NOT NULL, revision BIGINT NOT NULL, account_generation BIGINT NOT NULL, membership_generation BIGINT NOT NULL,
 profile_id TEXT NOT NULL, configuration_id TEXT NOT NULL, authority TEXT NOT NULL, privacy TEXT, policy TEXT, cache_key TEXT, period TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('local','pending','unresolved','settled','suppressed','expired','cancelled')),
 attempted BIGINT NOT NULL DEFAULT 0 CHECK(attempted IN (0,1)), evidence TEXT,
 result TEXT, result_bytes BIGINT NOT NULL DEFAULT 0 CHECK(result_bytes>=0), expires_at_ms BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT
);
CREATE TABLE explanation_requests (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, request_id TEXT NOT NULL, command_hash TEXT NOT NULL, operation_id TEXT NOT NULL,
 PRIMARY KEY(tenant_id,user_id,request_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES explanation_operations(tenant_id,id) ON DELETE RESTRICT
);
CREATE TABLE explanation_holds (
 tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL, scope TEXT NOT NULL, period TEXT NOT NULL, amount BIGINT NOT NULL CHECK(amount>=0),
 PRIMARY KEY(tenant_id,operation_id,scope),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES explanation_operations(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(scope,period) REFERENCES explanation_accounts(scope,period) ON DELETE RESTRICT
);
CREATE INDEX explanation_cache ON explanation_operations(tenant_id,user_id,cache_key,state);
CREATE INDEX explanation_responsibility ON explanation_operations(tenant_id,id);
CREATE INDEX explanation_exposure ON explanation_accounts(scope,held);
