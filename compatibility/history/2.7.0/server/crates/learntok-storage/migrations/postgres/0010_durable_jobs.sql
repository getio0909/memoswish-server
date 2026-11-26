-- 持久责任和预留独立于可删除的租户与账户；既有清理仍使用 account_erasure_jobs。
-- 内部任务与幂等配额账本；时间列统一以 Unix 毫秒保存。
CREATE TABLE background_jobs (
 tenant_id TEXT NOT NULL,
 id TEXT NOT NULL, kind TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 payload JSONB NOT NULL, user_id TEXT, requester_generation BIGINT,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','running','succeeded','dead')),
 attempts BIGINT NOT NULL DEFAULT 0 CHECK(attempts>=0),
 max_attempts BIGINT NOT NULL CHECK(max_attempts BETWEEN 1 AND 100 AND attempts<=max_attempts),
 available_at_ms BIGINT NOT NULL, lease_until_ms BIGINT NOT NULL DEFAULT 0,
 worker TEXT, token TEXT, result JSONB, error TEXT,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,kind,idempotency_key),
 CHECK((user_id IS NULL AND requester_generation IS NULL) OR (user_id IS NOT NULL AND requester_generation IS NOT NULL)),
 FOREIGN KEY(tenant_id,user_id,requester_generation) REFERENCES membership_generations(tenant_id,user_id,generation)
);
CREATE INDEX jobs_due ON background_jobs(tenant_id,kind,state,available_at_ms,lease_until_ms);
CREATE INDEX jobs_schedule ON background_jobs(kind,state,available_at_ms,lease_until_ms);
CREATE TABLE quota_operations (
 tenant_id TEXT NOT NULL,
 operation_id TEXT NOT NULL, metric TEXT NOT NULL, period TEXT NOT NULL,
 amount BIGINT NOT NULL CHECK(amount>=0),
 state TEXT NOT NULL CHECK(state IN ('reserved','committed','released')),
 PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT
);
CREATE TRIGGER erased_jobs BEFORE INSERT ON background_jobs FOR EACH ROW EXECUTE FUNCTION reject_erased_tenant();
CREATE FUNCTION validate_job_requester() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW.tenant_id,NEW.id,NEW.user_id,NEW.requester_generation) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.user_id,OLD.requester_generation) THEN
   RAISE EXCEPTION 'job ownership is immutable';
  END IF;
 ELSIF NEW.user_id IS NOT NULL THEN
  PERFORM user_id FROM tenant_memberships WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id AND generation=NEW.requester_generation FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'requester membership missing'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER job_requester BEFORE INSERT OR UPDATE ON background_jobs FOR EACH ROW EXECUTE FUNCTION validate_job_requester();
