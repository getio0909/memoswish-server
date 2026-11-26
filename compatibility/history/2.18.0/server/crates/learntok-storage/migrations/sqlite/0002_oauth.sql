-- OAuth 时间使用 Unix 秒，两个后端采用同一原子操作契约。
CREATE UNIQUE INDEX users_tenant_user ON users(tenant_id, id);
CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX oauth_clients_expiry ON oauth_clients(expires_at);
CREATE TABLE auth_browser_sessions (
    hash TEXT PRIMARY KEY,
    tenant_id TEXT,
    user_id TEXT,
    expires_at BIGINT NOT NULL,
    body TEXT NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX auth_browser_expiry ON auth_browser_sessions(expires_at);
CREATE TABLE oauth_authorization_requests (
    id TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL REFERENCES auth_browser_sessions(hash) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX oauth_requests_expiry ON oauth_authorization_requests(expires_at);
CREATE TABLE oauth_grants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    revoked BIGINT NOT NULL DEFAULT 0,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    UNIQUE(tenant_id, id)
);
CREATE INDEX oauth_grants_expiry ON oauth_grants(expires_at);
CREATE TABLE oauth_authorization_codes (
    hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BIGINT NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    FOREIGN KEY (tenant_id, grant_id) REFERENCES oauth_grants(tenant_id, id) ON DELETE CASCADE
);
CREATE TABLE oauth_tokens (
    hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BIGINT NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    FOREIGN KEY (tenant_id, grant_id) REFERENCES oauth_grants(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX oauth_tokens_grant ON oauth_tokens(tenant_id, grant_id);
-- 有界匿名注册使用单行写锁，在多副本间串行检查容量。
CREATE TABLE oauth_registry (id BIGINT PRIMARY KEY, value BIGINT NOT NULL);
INSERT INTO oauth_registry VALUES(1,0);
