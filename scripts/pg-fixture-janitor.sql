-- 两个 janitor 的回收事务串行执行，不影响仍持有专属连接的夹具。
BEGIN;
SET LOCAL statement_timeout = '10s';
DO $janitor$
DECLARE
    candidate record;
    metadata jsonb;
    created_at bigint;
    backend_pid integer;
    owner_backend_start timestamptz;
BEGIN
    PERFORM pg_advisory_xact_lock(1818583412, 1885824568);
    FOR candidate IN
        SELECT oid, nspname, obj_description(oid, 'pg_namespace') AS comment
        FROM pg_namespace
        WHERE nspname ~ '^learntok_test_[0-9a-f]{32}$'
          AND nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND (current_setting('memoswish_fixture.schema') = '' OR nspname = current_setting('memoswish_fixture.schema'))
    LOOP
        -- 未知或损坏元数据保留，前缀本身不代表所有权。
        BEGIN
            metadata := candidate.comment::jsonb;
            IF metadata->>'tool' IS DISTINCT FROM 'learntok-pg-fixture-v1'
                OR metadata->>'schema' IS DISTINCT FROM candidate.nspname
                OR jsonb_typeof(metadata->'worktree') IS DISTINCT FROM 'string'
                OR COALESCE(metadata->>'worktree', '') = ''
                OR jsonb_typeof(metadata->'branch') IS DISTINCT FROM 'string'
                OR COALESCE(metadata->>'branch', '') = ''
                OR jsonb_typeof(metadata->'pid') IS DISTINCT FROM 'number'
                OR (metadata->>'pid')::bigint <= 0
                OR jsonb_typeof(metadata->'created_at') IS DISTINCT FROM 'number'
                OR jsonb_typeof(metadata->'backend_pid') IS DISTINCT FROM 'number'
                OR jsonb_typeof(metadata->'backend_start') IS DISTINCT FROM 'string'
            THEN
                CONTINUE;
            END IF;
            created_at := (metadata->>'created_at')::bigint;
            backend_pid := (metadata->>'backend_pid')::integer;
            owner_backend_start := (metadata->>'backend_start')::timestamptz;
            IF created_at <= 0 OR backend_pid <= 0 OR NOT isfinite(owner_backend_start) THEN
                CONTINUE;
            END IF;
        EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN
            CONTINUE;
        END;
        IF created_at > EXTRACT(EPOCH FROM clock_timestamp()) - current_setting('memoswish_fixture.min_age_seconds')::numeric THEN
            CONTINUE;
        END IF;
        -- 数据库会话身份跨主机有效，起始时刻防止服务端 PID 复用误判。
        IF EXISTS (
            SELECT 1 FROM pg_stat_activity
            WHERE (pid = backend_pid AND owner_backend_start = pg_stat_activity.backend_start)
               OR (datid = (SELECT oid FROM pg_database WHERE datname = current_database())
                   AND application_name IN (candidate.nspname, candidate.nspname || '_owner'))
        ) THEN
            CONTINUE;
        END IF;
        -- 在执行前再次核对目录身份与完整注释，拒绝已替换或改标记的对象。
        IF NOT EXISTS (
            SELECT 1 FROM pg_namespace
            WHERE oid = candidate.oid AND nspname = candidate.nspname
              AND obj_description(oid, 'pg_namespace') = candidate.comment
              AND nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
        ) THEN
            CONTINUE;
        END IF;
        IF current_setting('memoswish_fixture.apply')::boolean THEN
            EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', candidate.nspname);
            RAISE NOTICE 'REMOVED stale owned schema %', candidate.nspname;
        ELSE
            RAISE NOTICE 'DRY RUN stale owned schema %', candidate.nspname;
        END IF;
    END LOOP;
END
$janitor$;
COMMIT;
