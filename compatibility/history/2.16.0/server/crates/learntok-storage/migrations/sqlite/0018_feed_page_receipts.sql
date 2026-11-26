-- 发页版本独立于 slot；历史会话不生成历史回执。
ALTER TABLE feed_sessions ADD COLUMN issuance_revision BIGINT NOT NULL DEFAULT 0 CHECK(issuance_revision>=0);
ALTER TABLE feed_sessions ADD COLUMN first_request_id TEXT;
ALTER TABLE feed_sessions ADD COLUMN issuance_context TEXT;
ALTER TABLE feed_sessions ADD COLUMN issuance_cursor TEXT;
ALTER TABLE feed_sessions ADD COLUMN expires_at_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE feed_sessions ADD COLUMN expired BIGINT NOT NULL DEFAULT 0 CHECK(expired IN (0,1));
UPDATE feed_sessions SET expires_at_ms=CAST((julianday(updated_at)-2440587.5)*86400000 AS BIGINT)+86400000 WHERE EXISTS(SELECT 1 FROM tenant_memberships m WHERE m.tenant_id=feed_sessions.tenant_id AND m.user_id=feed_sessions.user_id);
CREATE UNIQUE INDEX feed_first_request ON feed_sessions(tenant_id,user_id,first_request_id) WHERE first_request_id IS NOT NULL;
CREATE INDEX feed_session_expiry ON feed_sessions(expired,expires_at_ms);

-- 完整快照不引用活卡；删除会话必须同时删除其私有回执。
CREATE TABLE feed_page_receipts (
 tenant_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 issuance_key TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0),
 context TEXT NOT NULL,
 page TEXT NOT NULL,
 PRIMARY KEY(tenant_id,user_id,session_id,issuance_key),
 UNIQUE(tenant_id,user_id,session_id,revision),
 FOREIGN KEY(tenant_id,user_id,session_id) REFERENCES feed_sessions(tenant_id,user_id,id) ON DELETE CASCADE
);

-- 成员移除的会话范围与回执范围一致，不保留可重新访问的私有快照。
CREATE TRIGGER remove_member_feed_sessions AFTER DELETE ON tenant_memberships
 BEGIN DELETE FROM feed_sessions WHERE tenant_id=OLD.tenant_id AND user_id=OLD.user_id; END;
