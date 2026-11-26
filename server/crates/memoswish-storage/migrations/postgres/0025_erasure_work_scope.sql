-- 保留原租户复合主键及资产/配额外键；空分区只用于无租户的账户清理。
ALTER TABLE background_jobs ADD COLUMN work_scope TEXT NOT NULL DEFAULT 'tenant'
 CHECK((work_scope='tenant' AND tenant_id<>'') OR (work_scope='account' AND tenant_id='' AND kind='erasure' AND user_id IS NULL));
ALTER TABLE account_erasure_jobs ADD COLUMN partition_id TEXT NOT NULL DEFAULT '';
ALTER TABLE account_erasure_jobs ADD COLUMN progress TEXT NOT NULL DEFAULT 'pending' CHECK(progress IN ('pending','reconciling','blocked','complete'));
ALTER TABLE account_erasure_jobs ADD COLUMN revision BIGINT NOT NULL DEFAULT 0 CHECK(revision>=0);
ALTER TABLE account_erasure_jobs ADD COLUMN total_attempts BIGINT NOT NULL DEFAULT 0 CHECK(total_attempts>=0);
ALTER TABLE account_erasure_jobs ADD COLUMN assets_ack BIGINT NOT NULL DEFAULT 0 CHECK(assets_ack IN (0,1));
-- 移除窗口字段使旧 worker 在外部清理之前失败；升级前必须停掉旧二进制。
ALTER TABLE account_erasure_jobs DROP COLUMN drain_until_ms;
CREATE TABLE erasure_tombstone_work (
 tenant_id TEXT PRIMARY KEY REFERENCES erased_tenants(tenant_id) ON DELETE RESTRICT,
 job_id TEXT NOT NULL UNIQUE REFERENCES account_erasure_jobs(id) ON DELETE RESTRICT
);
CREATE TABLE erasure_sweep_cursor (id BIGINT PRIMARY KEY CHECK(id=1), after_tenant TEXT NOT NULL);
INSERT INTO erasure_sweep_cursor VALUES(1,'');
-- 受保护存储在外部调用前登记；无回执永远不能由时间推断完成。
CREATE TABLE managed_object_writes (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, store_id TEXT NOT NULL, object_key TEXT NOT NULL,
 outcome TEXT NOT NULL DEFAULT 'uncertain' CHECK(outcome IN ('uncertain','uploaded','cleanup_pending','cleaned')),
 version_kind TEXT NOT NULL DEFAULT 'unknown' CHECK(version_kind IN ('unknown','unversioned','version')),
 version_id TEXT,
 PRIMARY KEY(tenant_id,id),
 CHECK((version_kind='version' AND version_id IS NOT NULL) OR (version_kind<>'version' AND version_id IS NULL)),
 CHECK(outcome='uncertain' OR version_kind<>'unknown'),
 FOREIGN KEY(tenant_id,id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT
);
CREATE INDEX managed_write_cleanup ON managed_object_writes(tenant_id,outcome,id);

UPDATE account_erasure_jobs SET partition_id=COALESCE(body::jsonb->>'tenant_id','');
DROP TRIGGER erased_jobs ON background_jobs;
CREATE FUNCTION admit_scoped_work() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='erasure' THEN
  IF NOT EXISTS(SELECT 1 FROM account_erasure_jobs e WHERE e.id=NEW.id AND e.partition_id=NEW.tenant_id AND ((NEW.work_scope='account' AND NEW.tenant_id='') OR (NEW.work_scope='tenant' AND NEW.tenant_id<>''))) THEN RAISE EXCEPTION 'work admission rejected'; END IF;
 ELSE
  IF NEW.work_scope<>'tenant' THEN RAISE EXCEPTION 'work admission rejected'; END IF;
  PERFORM id FROM tenants WHERE id=NEW.tenant_id FOR SHARE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) THEN RAISE EXCEPTION 'work admission rejected'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER erased_jobs BEFORE INSERT ON background_jobs FOR EACH ROW EXECUTE FUNCTION admit_scoped_work();
CREATE FUNCTION enqueue_erasure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.partition_id=COALESCE(NEW.body::jsonb->>'tenant_id','');
 RETURN NEW;
END $$;
CREATE TRIGGER erasure_partition BEFORE INSERT ON account_erasure_jobs FOR EACH ROW EXECUTE FUNCTION enqueue_erasure();
CREATE FUNCTION schedule_erasure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope)
 VALUES(NEW.partition_id,NEW.id,'erasure',NEW.id,'{}',5,0,CASE WHEN NEW.partition_id='' THEN 'account' ELSE 'tenant' END);
 RETURN NEW;
END $$;
CREATE TRIGGER erasure_enqueue AFTER INSERT ON account_erasure_jobs FOR EACH ROW EXECUTE FUNCTION schedule_erasure();
INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope)
 SELECT partition_id,id,'erasure',id,'{}',5,0,CASE WHEN partition_id='' THEN 'account' ELSE 'tenant' END FROM account_erasure_jobs;
CREATE FUNCTION retain_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'erasure evidence is permanent'; END $$;
CREATE TRIGGER erasure_retain BEFORE DELETE ON account_erasure_jobs FOR EACH ROW EXECUTE FUNCTION retain_erasure();
CREATE FUNCTION immutable_work_scope() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.work_scope IS DISTINCT FROM OLD.work_scope THEN RAISE EXCEPTION 'work scope is immutable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER work_scope_immutable BEFORE UPDATE ON background_jobs FOR EACH ROW EXECUTE FUNCTION immutable_work_scope();

-- 已提交的旧擦除也移除 S16 私有输入，保留计费及版本证据。
UPDATE tts_syntheses SET audio=NULL,metadata=NULL,work='{}' WHERE EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=tts_syntheses.tenant_id);

-- 升级时清理旧擦除留下的提交正文和挂载回执，保留 provider、上传及费用证据。
DELETE FROM tts_submission_items WHERE EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=tts_submission_items.tenant_id) OR NOT EXISTS(SELECT 1 FROM users u WHERE u.id=tts_submission_items.user_id);
DELETE FROM tts_submissions WHERE EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=tts_submissions.tenant_id) OR NOT EXISTS(SELECT 1 FROM users u WHERE u.id=tts_submissions.user_id);
