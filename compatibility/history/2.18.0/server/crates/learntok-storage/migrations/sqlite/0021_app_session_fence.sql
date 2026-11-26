-- 第一方旧 JWT 的独立撤销域，不改变账户世代或 API/MCP 凭据。
CREATE TABLE app_session_fences (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revoked_through BIGINT NOT NULL
);

-- 持久请求者携带原始旧 JWT 签发时间，发布与挂载时复核独立注销屏障。
ALTER TABLE tts_requesters ADD COLUMN legacy_issued_at BIGINT;
