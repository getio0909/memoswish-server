-- 已解析事务绑定规范身份，handoff 通过事务索引参与跨 provider 解绑。
ALTER TABLE oidc_attempts ADD COLUMN identity_issuer TEXT;
ALTER TABLE oidc_attempts ADD COLUMN identity_subject TEXT;
CREATE INDEX oidc_attempt_identity ON oidc_attempts(identity_issuer,identity_subject);
ALTER TABLE oidc_handoffs ADD COLUMN attempt_id TEXT;
CREATE INDEX oidc_handoff_attempt ON oidc_handoffs(attempt_id);
