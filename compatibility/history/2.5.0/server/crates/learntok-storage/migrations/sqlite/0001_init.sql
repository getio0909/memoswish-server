-- LearnTok 初始 SQLite 模式。
-- 约定：所有业务表都带 tenant_id；时间列为 RFC 3339 文本；卡片主体以 JSON 存储便于协议演进。

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'self_hosted',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email          TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    scopes        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_used_at  TEXT,
    revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id);

CREATE TABLE IF NOT EXISTS usage_counters (
    tenant_id  TEXT NOT NULL,
    metric     TEXT NOT NULL,
    period     TEXT NOT NULL,
    amount     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, metric, period)
);

CREATE TABLE IF NOT EXISTS decks (
    id           TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    language     TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS cards (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    deck_id     TEXT NOT NULL,
    template    TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_cards_deck ON cards(tenant_id, deck_id, created_at);

CREATE TABLE IF NOT EXISTS bgm_tracks (
    id          TEXT NOT NULL,
    -- '' 表示共享曲库
    tenant_id   TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS memory_states (
    tenant_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    card_id      TEXT NOT NULL,
    stability    REAL NOT NULL,
    difficulty   REAL NOT NULL,
    reps         INTEGER NOT NULL,
    lapses       INTEGER NOT NULL,
    exposures    INTEGER NOT NULL,
    last_review  TEXT,
    due          TEXT,
    starred      INTEGER NOT NULL DEFAULT 0,
    last_rating  INTEGER,
    PRIMARY KEY (tenant_id, user_id, card_id)
);

CREATE TABLE IF NOT EXISTS feedback_events (
    tenant_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    card_id      TEXT NOT NULL,
    rating       INTEGER,
    body         TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_feedback_card ON feedback_events(tenant_id, user_id, card_id);

CREATE TABLE IF NOT EXISTS feed_sessions (
    id               TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    next_slot        INTEGER NOT NULL,
    recent_card_ids  TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id, id)
);
