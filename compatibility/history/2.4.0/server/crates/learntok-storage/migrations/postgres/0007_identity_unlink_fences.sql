-- 登录事务序列和解绑屏障不包含用户资料，保留到旧事务过期后仍可阻止晚到回调。
CREATE TABLE oidc_sequence (id BIGINT PRIMARY KEY, value BIGINT NOT NULL);
INSERT INTO oidc_sequence(id,value) VALUES(1,0);
ALTER TABLE oidc_attempts ADD COLUMN sequence BIGINT NOT NULL DEFAULT 0;
CREATE TABLE identity_unlink_fences (
 identity_hash TEXT PRIMARY KEY, sequence BIGINT NOT NULL
);
