-- 紧凑投递证据不随页面过期删除，也不依赖仍然存活的卡片。
ALTER TABLE feed_sessions ADD COLUMN attribution_start_slot BIGINT;
CREATE TABLE feed_deliveries (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    slot BIGINT NOT NULL CHECK(slot >= 0),
    delivery_id TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL,
    PRIMARY KEY(tenant_id,user_id,session_id,slot),
    FOREIGN KEY(tenant_id,user_id,session_id) REFERENCES feed_sessions(tenant_id,user_id,id) ON DELETE CASCADE
);
