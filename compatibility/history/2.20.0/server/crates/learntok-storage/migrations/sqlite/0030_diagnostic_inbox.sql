-- 诊断归成员本人，退出工作区及全局擦除均由外键级联删除。
CREATE TABLE diagnostic_reports (
 tenant_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 report_id TEXT NOT NULL,
 body TEXT NOT NULL CHECK(length(body)<=16384),
 privacy_revision BIGINT NOT NULL CHECK(privacy_revision>=0),
 created_at_ms BIGINT NOT NULL,
 expires_at_ms BIGINT NOT NULL,
 dispatch_started INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_started IN (0,1)),
 PRIMARY KEY(tenant_id,user_id,report_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
CREATE INDEX diagnostic_expiry ON diagnostic_reports(expires_at_ms);
CREATE INDEX diagnostic_tenant_expiry ON diagnostic_reports(tenant_id,expires_at_ms,report_id);
