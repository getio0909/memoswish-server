-- 在写事务内替换受约束列；保留父表、复合身份及全部外键。
-- 新的固定 guard 列承载等价扩展 CHECK，不关闭 foreign_keys 或使用 writable_schema。
DROP TRIGGER work_scope_immutable;
DROP TRIGGER erased_jobs_insert;
DROP TRIGGER erasure_enqueue;
ALTER TABLE background_jobs ADD COLUMN next_work_scope TEXT NOT NULL DEFAULT 'tenant';
UPDATE background_jobs SET next_work_scope=work_scope;
ALTER TABLE background_jobs DROP COLUMN work_scope;
ALTER TABLE background_jobs RENAME COLUMN next_work_scope TO work_scope;
ALTER TABLE background_jobs ADD COLUMN work_scope_guard BIGINT NOT NULL DEFAULT 1 CHECK(work_scope_guard=1 AND ((work_scope='tenant' AND tenant_id<>'' AND kind<>'maintenance') OR (work_scope='account' AND tenant_id='' AND kind='erasure' AND user_id IS NULL) OR (work_scope='maintenance' AND tenant_id='' AND kind='maintenance' AND user_id IS NULL)));
CREATE TRIGGER work_scope_immutable BEFORE UPDATE ON background_jobs WHEN NEW.work_scope IS NOT OLD.work_scope OR (OLD.work_scope='maintenance' AND (NEW.kind IS NOT OLD.kind OR NEW.idempotency_key IS NOT OLD.idempotency_key)) BEGIN SELECT RAISE(ABORT,'work identity is immutable'); END;
CREATE TRIGGER erasure_enqueue AFTER INSERT ON account_erasure_jobs BEGIN
 UPDATE account_erasure_jobs SET partition_id=COALESCE(json_extract(NEW.body,'$.tenant_id'),'') WHERE id=NEW.id;
 INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope)
 VALUES(COALESCE(json_extract(NEW.body,'$.tenant_id'),''),NEW.id,'erasure',NEW.id,'{}',5,0,CASE WHEN json_extract(NEW.body,'$.tenant_id') IS NULL THEN 'account' ELSE 'tenant' END);
END;
CREATE UNIQUE INDEX jobs_scoped_identity ON background_jobs(tenant_id,id,work_scope);
CREATE TABLE maintenance_tasks (
 partition_id TEXT NOT NULL DEFAULT '' CHECK(partition_id=''),
 work_scope TEXT NOT NULL DEFAULT 'maintenance' CHECK(work_scope='maintenance'),
 enabled BIGINT NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 id TEXT PRIMARY KEY,
 task_kind TEXT NOT NULL CHECK(task_kind IN ('feed_expiry','identity_expiry','oauth_expiry','tombstone_reconcile','erasure_recovery','import_recovery','speech_recovery','attachment_recovery','explanation_recovery','diagnostic_recovery','password_expiry','retention')),
 payload_version BIGINT NOT NULL CHECK(payload_version=1),
 target_tenant TEXT NOT NULL DEFAULT '', policy TEXT NOT NULL DEFAULT '{}',
 cursor TEXT NOT NULL DEFAULT '[]', cycle BIGINT NOT NULL DEFAULT 0 CHECK(cycle>=0),
 CHECK((task_kind='retention' AND target_tenant<>'') OR (task_kind<>'retention' AND target_tenant='' AND policy='{}')),
 FOREIGN KEY(partition_id,id,work_scope) REFERENCES background_jobs(tenant_id,id,work_scope) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
-- 接纳凭据仅证明有界单项已移交，不含第二租约、重试或队列状态。
CREATE TABLE maintenance_admissions (
 task_id TEXT NOT NULL REFERENCES maintenance_tasks(id) ON DELETE RESTRICT,
 cycle BIGINT NOT NULL, tenant_id TEXT NOT NULL, item_id TEXT NOT NULL,
 admission_id TEXT NOT NULL UNIQUE, admitted_at_ms BIGINT NOT NULL,
 PRIMARY KEY(task_id,cycle,tenant_id,item_id)
);
CREATE TRIGGER erased_jobs_insert BEFORE INSERT ON background_jobs
 WHEN (NEW.work_scope='maintenance' AND NOT EXISTS(SELECT 1 FROM maintenance_tasks m WHERE m.id=NEW.id AND NEW.idempotency_key=NEW.id AND NEW.payload='{}'))
 OR (NEW.work_scope<>'maintenance' AND ((NEW.kind='erasure' AND NOT EXISTS(SELECT 1 FROM account_erasure_jobs e WHERE e.id=NEW.id AND e.partition_id=NEW.tenant_id AND ((NEW.work_scope='account' AND NEW.tenant_id='') OR (NEW.work_scope='tenant' AND NEW.tenant_id<>''))))
 OR (NEW.kind<>'erasure' AND (NEW.work_scope<>'tenant' OR NOT EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) OR EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id)))))
 BEGIN SELECT RAISE(ABORT,'work admission rejected'); END;
CREATE TRIGGER maintenance_identity_immutable BEFORE UPDATE ON maintenance_tasks
 WHEN NEW.id IS NOT OLD.id OR NEW.task_kind IS NOT OLD.task_kind OR NEW.payload_version IS NOT OLD.payload_version OR NEW.target_tenant IS NOT OLD.target_tenant OR NEW.policy IS NOT OLD.policy OR NEW.partition_id IS NOT OLD.partition_id OR NEW.work_scope IS NOT OLD.work_scope
 BEGIN SELECT RAISE(ABORT,'maintenance identity is immutable'); END;
-- 最小接纳证据只追加；不能通过删配置隐藏仍存在的维护任务。
CREATE TRIGGER maintenance_task_retain BEFORE DELETE ON maintenance_tasks BEGIN SELECT RAISE(ABORT,'maintenance task identity is permanent'); END;
CREATE TRIGGER maintenance_admission_immutable BEFORE UPDATE ON maintenance_admissions BEGIN SELECT RAISE(ABORT,'maintenance admission is immutable'); END;
CREATE TRIGGER maintenance_admission_retain BEFORE DELETE ON maintenance_admissions BEGIN SELECT RAISE(ABORT,'maintenance admission is permanent'); END;
-- 有界目录和墓碑业务查找沿用持久键顺序，不在应用层遍历历史任务。
CREATE INDEX maintenance_catalog ON maintenance_tasks(task_kind,enabled,id);
CREATE INDEX erasure_partition_lookup ON account_erasure_jobs(partition_id,id);
-- 新责任在受理事务内唤醒 queued 调度；不重置游标、不修改 running owner 或业务预算。
CREATE TRIGGER maintenance_erasure_wake AFTER INSERT ON account_erasure_jobs BEGIN
 UPDATE background_jobs SET available_at_ms=0
 WHERE work_scope='maintenance' AND state='queued'
 AND id IN (SELECT id FROM maintenance_tasks WHERE task_kind IN ('tombstone_reconcile','erasure_recovery'));
END;

-- 仅新接收报告捕获原始授权；旧收件箱缺少证据时不自动外发。
ALTER TABLE diagnostic_reports ADD COLUMN forward_authority TEXT;
