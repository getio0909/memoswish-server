-- 历史账户不填充同意；用途状态随成员移除，账户证据随销户删除。
CREATE TABLE privacy_accounts (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 revision BIGINT NOT NULL CHECK(revision>=0),
 body TEXT NOT NULL
);
CREATE TABLE privacy_purposes (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, body TEXT NOT NULL,
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);

-- 部署政策由一致配置的实例启动安装，持久工作不能沿用已更换的提供者政策。
CREATE TABLE privacy_deployment_policy (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);

CREATE INDEX privacy_requester_work ON tts_requesters(user_id,tenant_id,synthesis_id);
