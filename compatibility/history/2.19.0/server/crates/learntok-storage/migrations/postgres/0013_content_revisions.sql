-- 历史曲库从版本 1 开始；卡片内嵌曲目由 codec 缺省兼容。
ALTER TABLE bgm_tracks ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 4294967295);
UPDATE bgm_tracks SET body = jsonb_set(body, '{revision}', to_jsonb(revision));
