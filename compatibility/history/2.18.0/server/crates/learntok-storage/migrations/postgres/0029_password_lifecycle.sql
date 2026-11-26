-- 本地邮箱证明不从旧地址或上游声明推断；升级保留原口令和世代。
CREATE TABLE password_credentials (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 0 CHECK(version >= 0),
    verified_email TEXT
);
INSERT INTO password_credentials(user_id) SELECT id FROM users;

-- 只存用途分域的摘要；重发替换本用途旧证明，不持久保存邮件正文。
CREATE TABLE password_challenges (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset')),
    digest TEXT NOT NULL UNIQUE,
    destination TEXT NOT NULL,
    credential_version BIGINT NOT NULL CHECK(credential_version >= 0),
    generation BIGINT NOT NULL CHECK(generation >= 0),
    expires_at BIGINT NOT NULL,
    PRIMARY KEY(user_id,purpose)
);
CREATE INDEX password_challenge_expiry ON password_challenges(expires_at);
