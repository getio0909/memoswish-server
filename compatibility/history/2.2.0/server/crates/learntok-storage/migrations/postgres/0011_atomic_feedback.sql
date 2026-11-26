-- 历史投影默认版本零；原始历史事件不声明投影完成状态。
ALTER TABLE memory_states ADD COLUMN projection_version BIGINT NOT NULL DEFAULT 0 CHECK (projection_version >= 0);
ALTER TABLE feedback_events ADD COLUMN payload_hash TEXT;
