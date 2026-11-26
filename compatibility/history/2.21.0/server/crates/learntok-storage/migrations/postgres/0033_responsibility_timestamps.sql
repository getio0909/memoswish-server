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
CREATE FUNCTION ops_background_jobs_created() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 NEW.enqueued_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT); RETURN NEW; END $$;
CREATE TRIGGER ops_background_jobs_created BEFORE INSERT ON background_jobs FOR EACH ROW EXECUTE FUNCTION ops_background_jobs_created();
CREATE FUNCTION ops_account_erasure_jobs_created() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 NEW.responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT); RETURN NEW; END $$;
CREATE TRIGGER ops_account_erasure_jobs_created BEFORE INSERT ON account_erasure_jobs FOR EACH ROW EXECUTE FUNCTION ops_account_erasure_jobs_created();
CREATE FUNCTION ops_asset_upload_attempts_created() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 NEW.responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT); RETURN NEW; END $$;
CREATE TRIGGER ops_asset_upload_attempts_created BEFORE INSERT ON asset_upload_attempts FOR EACH ROW EXECUTE FUNCTION ops_asset_upload_attempts_created();
CREATE FUNCTION ops_managed_object_writes_created() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 NEW.responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT); RETURN NEW; END $$;
CREATE TRIGGER ops_managed_object_writes_created BEFORE INSERT ON managed_object_writes FOR EACH ROW EXECUTE FUNCTION ops_managed_object_writes_created();
CREATE FUNCTION ops_jobs_time_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.enqueued_at_ms IS DISTINCT FROM OLD.enqueued_at_ms THEN RAISE EXCEPTION 'job enqueue time is immutable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER ops_jobs_time_immutable BEFORE UPDATE ON background_jobs FOR EACH ROW EXECUTE FUNCTION ops_jobs_time_immutable();
-- 完成后晚到责任开启新周期；未完成的历史 unknown 在重试中仍保持 unknown。
CREATE FUNCTION ops_erasure_reopened() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.progress='complete' AND NEW.progress<>'complete' THEN NEW.responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT); END IF; RETURN NEW; END $$;
CREATE TRIGGER ops_erasure_reopened BEFORE UPDATE ON account_erasure_jobs FOR EACH ROW EXECUTE FUNCTION ops_erasure_reopened();

-- 到期候选使用真实 expires_at；不推断运营方未配置的保留期限。
CREATE INDEX ops_oauth_token_expiry ON oauth_tokens(expires_at);

-- 已完成的正常写入遇到墓碑才产生新清理周期；一直未决的写入不重置年龄。
CREATE FUNCTION ops_erased_objects() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 UPDATE managed_object_writes SET responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND outcome='uploaded';
 UPDATE asset_upload_attempts SET responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT) WHERE tenant_id=NEW.tenant_id AND outcome='uploaded' AND EXISTS(SELECT 1 FROM asset_upload_intents i WHERE i.tenant_id=asset_upload_attempts.tenant_id AND i.published_attempt=asset_upload_attempts.id);
 RETURN NEW; END $$;
CREATE TRIGGER ops_erased_objects AFTER INSERT ON erased_tenants FOR EACH ROW EXECUTE FUNCTION ops_erased_objects();
CREATE FUNCTION ops_managed_cleanup_cycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.outcome='uploaded' AND NEW.outcome='cleanup_pending' AND NOT EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) THEN NEW.responsibility_at_ms=CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT); END IF; RETURN NEW; END $$;
CREATE TRIGGER ops_managed_cleanup_cycle BEFORE UPDATE ON managed_object_writes FOR EACH ROW EXECUTE FUNCTION ops_managed_cleanup_cycle();
