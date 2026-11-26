-- 在既有调度权威中扩展全局维护作用域，不伪造租户。
-- 旧版本的匿名 CHECK 名称由 PostgreSQL 分配，按确切列归属找到唯一原约束。
DO $$ DECLARE scope_constraint TEXT; BEGIN
 SELECT c.conname INTO STRICT scope_constraint FROM pg_constraint c
 JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
 WHERE c.conrelid='background_jobs'::regclass AND c.contype='c' AND a.attname='work_scope';
 EXECUTE format('ALTER TABLE background_jobs DROP CONSTRAINT %I',scope_constraint);
END $$;
ALTER TABLE background_jobs ADD CONSTRAINT background_jobs_work_scope_check CHECK(
 (work_scope='tenant' AND tenant_id<>'' AND kind<>'maintenance') OR (work_scope='account' AND tenant_id='' AND kind='erasure' AND user_id IS NULL) OR (work_scope='maintenance' AND tenant_id='' AND kind='maintenance' AND user_id IS NULL));
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
CREATE OR REPLACE FUNCTION admit_scoped_work() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.work_scope='maintenance' THEN
  IF NOT EXISTS(SELECT 1 FROM maintenance_tasks m WHERE m.id=NEW.id AND NEW.idempotency_key=NEW.id AND CAST(NEW.payload AS TEXT)='{}') THEN RAISE EXCEPTION 'work admission rejected'; END IF;
 ELSIF NEW.kind='erasure' THEN
  IF NOT EXISTS(SELECT 1 FROM account_erasure_jobs e WHERE e.id=NEW.id AND e.partition_id=NEW.tenant_id AND ((NEW.work_scope='account' AND NEW.tenant_id='') OR (NEW.work_scope='tenant' AND NEW.tenant_id<>''))) THEN RAISE EXCEPTION 'work admission rejected'; END IF;
 ELSE
  IF NEW.work_scope<>'tenant' THEN RAISE EXCEPTION 'work admission rejected'; END IF;
  PERFORM id FROM tenants WHERE id=NEW.tenant_id FOR SHARE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) THEN RAISE EXCEPTION 'work admission rejected'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION immutable_maintenance_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.task_kind IS DISTINCT FROM OLD.task_kind OR NEW.payload_version IS DISTINCT FROM OLD.payload_version OR NEW.target_tenant IS DISTINCT FROM OLD.target_tenant OR NEW.policy IS DISTINCT FROM OLD.policy OR NEW.partition_id IS DISTINCT FROM OLD.partition_id OR NEW.work_scope IS DISTINCT FROM OLD.work_scope THEN RAISE EXCEPTION 'maintenance identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER maintenance_identity_immutable BEFORE UPDATE ON maintenance_tasks FOR EACH ROW EXECUTE FUNCTION immutable_maintenance_identity();
CREATE FUNCTION immutable_maintenance_work() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.work_scope='maintenance' AND (NEW.kind IS DISTINCT FROM OLD.kind OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key) THEN RAISE EXCEPTION 'work identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER maintenance_work_immutable BEFORE UPDATE ON background_jobs FOR EACH ROW EXECUTE FUNCTION immutable_maintenance_work();
-- 最小接纳证据只追加；不能通过删配置隐藏仍存在的维护任务。
CREATE FUNCTION retain_maintenance_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'maintenance identity is permanent'; END $$;
CREATE TRIGGER maintenance_task_retain BEFORE DELETE ON maintenance_tasks FOR EACH ROW EXECUTE FUNCTION retain_maintenance_identity();
CREATE TRIGGER maintenance_admission_retain BEFORE UPDATE OR DELETE ON maintenance_admissions FOR EACH ROW EXECUTE FUNCTION retain_maintenance_identity();
-- 有界目录和墓碑业务查找沿用持久键顺序，不在应用层遍历历史任务。
CREATE INDEX maintenance_catalog ON maintenance_tasks(task_kind,enabled,id);
CREATE INDEX erasure_partition_lookup ON account_erasure_jobs(partition_id,id);
-- 新责任在受理事务内唤醒 queued 调度；不重置游标、不修改 running owner 或业务预算。
CREATE FUNCTION wake_erasure_maintenance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE background_jobs SET available_at_ms=0
 WHERE work_scope='maintenance' AND state='queued'
 AND id IN (SELECT id FROM maintenance_tasks WHERE task_kind IN ('tombstone_reconcile','erasure_recovery'));
 RETURN NEW;
END $$;
CREATE TRIGGER maintenance_erasure_wake AFTER INSERT ON account_erasure_jobs FOR EACH ROW EXECUTE FUNCTION wake_erasure_maintenance();

-- 仅新接收报告捕获原始授权；旧收件箱缺少证据时不自动外发。
ALTER TABLE diagnostic_reports ADD COLUMN forward_authority TEXT;
