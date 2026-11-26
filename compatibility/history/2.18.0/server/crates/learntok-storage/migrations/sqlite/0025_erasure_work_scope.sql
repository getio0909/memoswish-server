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

UPDATE account_erasure_jobs SET partition_id=COALESCE(json_extract(body,'$.tenant_id'),'');
DROP TRIGGER erased_jobs_insert;
CREATE TRIGGER erased_jobs_insert BEFORE INSERT ON background_jobs
 WHEN (NEW.kind='erasure' AND NOT EXISTS(SELECT 1 FROM account_erasure_jobs e WHERE e.id=NEW.id AND e.partition_id=NEW.tenant_id AND ((NEW.work_scope='account' AND NEW.tenant_id='') OR (NEW.work_scope='tenant' AND NEW.tenant_id<>''))))
 OR (NEW.kind<>'erasure' AND (NEW.work_scope<>'tenant' OR NOT EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) OR EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id)))
 BEGIN SELECT RAISE(ABORT,'work admission rejected'); END;
CREATE TRIGGER erasure_enqueue AFTER INSERT ON account_erasure_jobs BEGIN
 UPDATE account_erasure_jobs SET partition_id=COALESCE(json_extract(NEW.body,'$.tenant_id'),'') WHERE id=NEW.id;
 INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope)
 VALUES(COALESCE(json_extract(NEW.body,'$.tenant_id'),''),NEW.id,'erasure',NEW.id,'{}',5,0,CASE WHEN json_extract(NEW.body,'$.tenant_id') IS NULL THEN 'account' ELSE 'tenant' END);
END;
INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope)
 SELECT partition_id,id,'erasure',id,'{}',5,0,CASE WHEN partition_id='' THEN 'account' ELSE 'tenant' END FROM account_erasure_jobs;
CREATE TRIGGER erasure_retain BEFORE DELETE ON account_erasure_jobs BEGIN SELECT RAISE(ABORT,'erasure evidence is permanent'); END;
CREATE TRIGGER work_scope_immutable BEFORE UPDATE ON background_jobs WHEN NEW.work_scope IS NOT OLD.work_scope BEGIN SELECT RAISE(ABORT,'work scope is immutable'); END;

-- 已提交的旧擦除也移除 S16 私有输入，保留计费及版本证据。
UPDATE tts_syntheses SET audio=NULL,metadata=NULL,work='{}' WHERE EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=tts_syntheses.tenant_id);

-- 升级时清理旧擦除留下的提交正文和挂载回执，保留 provider、上传及费用证据。
DELETE FROM tts_submission_items WHERE EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=tts_submission_items.tenant_id) OR NOT EXISTS(SELECT 1 FROM users u WHERE u.id=tts_submission_items.user_id);
DELETE FROM tts_submissions WHERE EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=tts_submissions.tenant_id) OR NOT EXISTS(SELECT 1 FROM users u WHERE u.id=tts_submissions.user_id);
