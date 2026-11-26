-- Apple 通知幂等与身份状态；撤销世代让既有无状态 App JWT 立即失效。
CREATE TABLE identity_events (
 issuer TEXT NOT NULL,event_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,
 PRIMARY KEY(issuer,event_hash)
);
CREATE TABLE identity_status (
 issuer TEXT NOT NULL,subject TEXT NOT NULL,last_event_at BIGINT NOT NULL,
 last_event_kind TEXT NOT NULL,email_forwarding TEXT,revoked_before BIGINT NOT NULL DEFAULT 0,permanently_deleted BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(issuer,subject),
 FOREIGN KEY(issuer,subject) REFERENCES federated_identities(issuer,subject) ON DELETE CASCADE
);
CREATE TABLE user_auth_epochs (
 tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,generation BIGINT NOT NULL,
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX identity_events_expiry ON identity_events(expires_at);
CREATE INDEX recent_auth_expiry ON recent_authentication(expires_at);
CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs(expires_at);
