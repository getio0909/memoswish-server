-- BGM 暂存与不可变结果绑定 S15 上传，不另建租约或费用账本。
CREATE TABLE bgm_publications (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    command_hash TEXT NOT NULL,
    authority TEXT NOT NULL,
    track TEXT NOT NULL,
    expected_revision BIGINT,
    audio BYTEA,
    outcome TEXT NOT NULL DEFAULT 'pending' CHECK(outcome IN ('pending','published','rejected')),
    result TEXT,
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,user_id,request_id),
    FOREIGN KEY(tenant_id,id) REFERENCES asset_upload_intents(tenant_id,id)
);
