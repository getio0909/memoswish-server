-- 写入先共享锁住父租户，擦除先排他锁住父租户，再执行墓碑和删除。
-- 等待擦除提交的旧语句必须重新检查父行存在性，不能只依赖旧语句快照中的墓碑。
CREATE OR REPLACE FUNCTION reject_erased_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- shared BGM 的空租户是既有全局曲库约定。
 IF TG_TABLE_NAME='bgm_tracks' AND NEW.tenant_id='' THEN RETURN NEW; END IF;
 IF NEW.tenant_id IS NULL THEN RETURN NEW; END IF;
 PERFORM id FROM tenants WHERE id=NEW.tenant_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'tenant missing or erased'; END IF;
 IF EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) THEN
  RAISE EXCEPTION 'tenant erased';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION reject_missing_user() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM id FROM users WHERE tenant_id=NEW.tenant_id AND id=NEW.user_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'user missing or erased'; END IF;
 RETURN NEW;
END $$;
