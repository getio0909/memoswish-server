-- 墓碑提交后首次观察任务时设置；旧任务也必须完整等待排空窗口。
ALTER TABLE account_erasure_jobs ADD COLUMN drain_until_ms BIGINT;
