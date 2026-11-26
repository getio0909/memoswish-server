-- 历史责任保持 NULL，不用调度时间或迁移执行时间补造年龄。
ALTER TABLE background_jobs ADD COLUMN enqueued_at_ms BIGINT;
ALTER TABLE account_erasure_jobs ADD COLUMN responsibility_at_ms BIGINT;
ALTER TABLE asset_upload_attempts ADD COLUMN responsibility_at_ms BIGINT;
ALTER TABLE managed_object_writes ADD COLUMN responsibility_at_ms BIGINT;
CREATE INDEX ops_jobs_pending_age ON background_jobs(kind,enqueued_at_ms) WHERE state<>'succeeded';
CREATE INDEX ops_erasure_pending_age ON account_erasure_jobs(responsibility_at_ms) WHERE progress<>'complete';
CREATE INDEX ops_asset_pending_age ON asset_upload_attempts(outcome,responsibility_at_ms);
CREATE INDEX ops_managed_pending_age ON managed_object_writes(outcome,responsibility_at_ms);
-- 新 writer 与升级后旧插入入口均由数据库时钟起算；claim/retry 不修改时间。
CREATE TRIGGER ops_background_jobs_created AFTER INSERT ON background_jobs WHEN NEW.enqueued_at_ms IS NULL BEGIN
 UPDATE background_jobs SET enqueued_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
END;
CREATE TRIGGER ops_jobs_time_immutable BEFORE UPDATE OF enqueued_at_ms ON background_jobs WHEN OLD.enqueued_at_ms IS NOT NULL AND NEW.enqueued_at_ms IS NOT OLD.enqueued_at_ms BEGIN SELECT RAISE(ABORT,'job enqueue time is immutable'); END;
CREATE TRIGGER ops_account_erasure_jobs_created AFTER INSERT ON account_erasure_jobs WHEN NEW.responsibility_at_ms IS NULL BEGIN
 UPDATE account_erasure_jobs SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE id=NEW.id;
END;
CREATE TRIGGER ops_asset_upload_attempts_created AFTER INSERT ON asset_upload_attempts WHEN NEW.responsibility_at_ms IS NULL BEGIN
 UPDATE asset_upload_attempts SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
END;
CREATE TRIGGER ops_managed_object_writes_created AFTER INSERT ON managed_object_writes WHEN NEW.responsibility_at_ms IS NULL BEGIN
 UPDATE managed_object_writes SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
END;
-- 完成后晚到责任开启新周期；未完成的历史 unknown 在重试中仍保持 unknown。
CREATE TRIGGER ops_erasure_reopened AFTER UPDATE OF progress ON account_erasure_jobs WHEN OLD.progress='complete' AND NEW.progress<>'complete' BEGIN
 UPDATE account_erasure_jobs SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE id=NEW.id;
END;

-- 到期候选使用真实 expires_at；不推断运营方未配置的保留期限。
CREATE INDEX ops_oauth_token_expiry ON oauth_tokens(expires_at);

-- 已完成的正常写入遇到墓碑才产生新清理周期；一直未决的写入不重置年龄。
CREATE TRIGGER ops_erased_objects AFTER INSERT ON erased_tenants BEGIN
 UPDATE managed_object_writes SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND outcome='uploaded';
 UPDATE asset_upload_attempts SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND outcome='uploaded' AND EXISTS(SELECT 1 FROM asset_upload_intents i WHERE i.tenant_id=asset_upload_attempts.tenant_id AND i.published_attempt=asset_upload_attempts.id);
END;
CREATE TRIGGER ops_managed_cleanup_cycle AFTER UPDATE OF outcome ON managed_object_writes WHEN OLD.outcome='uploaded' AND NEW.outcome='cleanup_pending' AND NOT EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN
 UPDATE managed_object_writes SET responsibility_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
END;
