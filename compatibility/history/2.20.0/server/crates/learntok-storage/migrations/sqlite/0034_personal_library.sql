-- 显式决定独立于复习，随成员生命周期擦除；卡片删除后保留无正文身份。
CREATE TABLE personal_favorites (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    starred INTEGER NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant_id,user_id,card_id),
    FOREIGN KEY (tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
CREATE TABLE favorite_operations (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    command TEXT NOT NULL,
    receipt TEXT NOT NULL,
    PRIMARY KEY (tenant_id,user_id,operation_id),
    FOREIGN KEY (tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
CREATE INDEX personal_history_key ON feedback_events(tenant_id,user_id,received_at,event_id);

-- 游标绑定数据库安装，不能跨部署复用。
CREATE TABLE personal_library_namespace (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
INSERT INTO personal_library_namespace VALUES(1,lower(hex(randomblob(16))));
