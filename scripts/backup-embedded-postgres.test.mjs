import './legacy-environment.cjs';
// OSS PostgreSQL + 本地对象存储的完整安装恢复；仅操作本次成功创建的随机数据库。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { prepareRecoveryBinary, recoveryFixture } from './backup-embedded-fixture.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const admin = process.env.MEMOSWISH_TEST_POSTGRES_URL;
assert(admin?.trim(), 'MEMOSWISH_TEST_POSTGRES_URL is required; PostgreSQL recovery must not skip');
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('MEMOSWISH_') && key !== 'DATABASE_URL'));

function sql(url, query) {
  // 不把连接参数、SQL 或包含密钥的子进程错误传播到日志。
  const result = spawnSync('psql', ['-XAt', '--no-password', '--set=ON_ERROR_STOP=1', '--dbname', url],
    { env: environment, input: query, encoding: 'utf8' });
  assert.equal(result.status, 0, 'PostgreSQL recovery fixture SQL failed');
  return result.stdout.trim();
}

test('PostgreSQL custom dump restores into a fresh database and directory with original installation state', async t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'memoswish-pg-recovery-'));
  const binary = path.join(tmp, 'memoswishd');
  const source = path.join(tmp, 'source');
  const backup = path.join(tmp, 'backup');
  const fresh = path.join(tmp, 'fresh');
  const config = path.join(tmp, 'source.toml');
  const single = path.join(tmp, 'single.toml');
  const key = 'A'.repeat(43);
  const owned = [];
  let server;
  let restored;
  const { start, stop, request, reseal } = recoveryFixture({ root, tmp, binary, environment });
  function createDatabase() {
    const name = `memoswish_recovery_${randomUUID().replaceAll('-', '')}`;
    const url = new URL(admin);
    url.pathname = `/${name}`;
    // 仅登记 CREATE 成功的资源；不接受用户输入的数据库名作为清理范围。
    sql(admin, `CREATE DATABASE "${name}" TEMPLATE template0;`);
    owned.push(name);
    sql(admin, `COMMENT ON DATABASE "${name}" IS 'memoswish-c13-recovery:${process.pid}';`);
    return url.toString();
  }
  function recover(mode, input, output, database, extra = []) {
    const started = performance.now();
    const result = spawnSync(path.join(root, 'scripts', mode === 'backup' ? 'backup-embedded' : 'restore-embedded'),
      [input, output, '--memoswishd', binary, '--database-url', database, ...extra],
      { env: environment, cwd: root, encoding: 'utf8' });
    assert.ifError(result.error);
    t.diagnostic(`Recovery ${mode}: ${((performance.now() - started) / 1000).toFixed(3)}s`);
    return result;
  }
  function configuration(database, multi) {
    return `database_url = ${JSON.stringify(database)}
mode = "${multi ? 'multi_tenant' : 'single_user'}"
registration_open = true
seed_demo = false
[tts]
default_engine = "placeholder"
auto_detect_espeak = false
[oidc]
public_base_url = "https://learn.example.test"
return_uris = ["com.memoswish.app:/auth/callback"]
encryption_key = "${key}"
[[oidc.providers]]
id = "example"
name = "Example"
issuer = "https://auth.example.test"
discovery_url = "https://auth.example.test/.well-known/openid-configuration"
client_id = "c13"
client_secret = "synthetic-provider-secret"
allowed_hosts = ["auth.example.test"]
`;
  }
  try {
    prepareRecoveryBinary(process.env.MEMOSWISH_RECOVERY_BINARY || path.join(root, 'server/target/debug/memoswishd'), binary);
    const originalDatabase = createDatabase();
    const newDatabase = createDatabase();
    fs.writeFileSync(config, configuration(originalDatabase, true), { mode: 0o600 });
    fs.writeFileSync(single, configuration(originalDatabase, false), { mode: 0o600 });
    server = await start(source, single);
    // 冷恢复只需一张有真实合成媒体的卡片；演示卡组的种类由 live E2E 覆盖。
    async function tool(name, args) {
      const response = await request(server, '/mcp', {
        jsonrpc: '2.0', id: name, method: 'tools/call', params: { name, arguments: args },
      });
      assert.equal(response.result.isError, false, `recovery fixture ${name} must succeed`);
      return response.result.structuredContent;
    }
    const deck = await tool('deck_create', { title: 'Recovery fixture', language: 'en-US' });
    const cards = await tool('card_upsert', {
      cards: [{ deck_id: deck.id, template: 'concept', front: { title: 'Recovery' }, back: { title: 'Committed state' } }],
      auto_tts: true,
    });
    assert.equal(cards.result.length, 1);
    assert(cards.result[0].tts?.audio.url, 'fixture must contain synthesized media');
    const page = await request(server, '/v1/feed');
    const item = page.items[0];
    assert.equal(item.card.id, cards.result[0].id);
    const feedback = {
      session_id: page.session_id, client_id: 'c13-pg', sent_at: new Date().toISOString(),
      events: [{ event_id: 'c13-pg-review', card_id: item.card.id, slot: item.slot,
        shown_at: new Date().toISOString(), dwell_time_ms: 3000, loop_count: 1, swipe_velocity: 1.2,
        swipe_direction: 'next', flipped: false, double_tapped: true, long_pressed: false, muted: false }],
    };
    assert.equal((await request(server, '/v1/feedback', feedback)).accepted, 1);
    const mediaPath = item.card.tts.audio.url;
    const mediaResponse = await fetch(`${server.url}${mediaPath}`);
    assert.equal(mediaResponse.status, 200);
    const media = Buffer.from(await mediaResponse.arrayBuffer());
    assert(media.length > 44);
    await stop(server);
    server = undefined;
    server = await start(source, config);
    const credentials = { email: 'c13-pg@example.test', password: 'synthetic-password-123' };
    const auth = await request(server, '/v1/auth/register', { ...credentials, display_name: 'C13 PG' });
    assert.notEqual(recover('backup', source, path.join(tmp, 'live-refused'), originalDatabase, ['--config', config]).status, 0);
    assert(!fs.existsSync(path.join(tmp, 'live-refused')));
    await stop(server);
    server = undefined;

    const pending = { id: 'c13-pg-cleanup', tenant_id: 'c13-pg-erased', purge_assets: true, credentials: [] };
    const revocation = { id: 'c13-pg-revoke', tenant_id: 'c13-pg-oidc', purge_assets: false, credentials: [['example', 'synthetic-ciphertext']] };
    sql(originalDatabase, `INSERT INTO erased_tenants VALUES('c13-pg-erased');
      INSERT INTO erased_users VALUES('c13-pg-erased','c13-pg-erased-user');
      INSERT INTO account_erasure_jobs(id,body) VALUES('c13-pg-cleanup','${JSON.stringify(pending)}');
      INSERT INTO account_erasure_jobs(id,body) VALUES('c13-pg-revoke','${JSON.stringify(revocation)}');`);
    const erasedAssets = path.join(source, 'assets/tenants/c13-pg-erased');
    fs.mkdirSync(erasedAssets, { recursive: true });
    fs.writeFileSync(path.join(erasedAssets, 'late.wav'), 'synthetic late write');
    const saved = recover('backup', source, backup, originalDatabase, ['--config', config]);
    assert.equal(saved.status, 0, saved.stderr);
    assert.equal(fs.readFileSync(path.join(backup, 'database.dump')).subarray(0, 5).toString(), 'PGDMP');
    assert(fs.readFileSync(path.join(backup, 'learntokd.toml'), 'utf8').includes(key));
    const sourceKey = fs.readFileSync(path.join(source, 'jwt_secret'), 'utf8').trim();
    assert(fs.readFileSync(path.join(backup, 'learntokd.toml'), 'utf8').includes(sourceKey));

    // 负例即使重新封装校验和仍必须拒绝，并且不能向新库写入任何表。
    for (const [name, mutate] of [
      ['wrong-major', directory => {
        const file = path.join(directory, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(file));
        manifest.postgres_major += 1;
        fs.writeFileSync(file, JSON.stringify(manifest));
      }],
      ['wrong-version', directory => {
        const file = path.join(directory, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(file));
        manifest.application_version = 'memoswishd 9.0.0';
        fs.writeFileSync(file, JSON.stringify(manifest));
      }],
      ['wrong-migrations', directory => {
        const file = path.join(directory, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(file));
        manifest.schema.pop();
        fs.writeFileSync(file, JSON.stringify(manifest));
      }],
      ['missing-jwt', directory => {
        const file = path.join(directory, 'learntokd.toml');
        fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(/^jwt_secret = .*$/m, 'jwt_secret = ""'));
      }],
      ['missing-oidc', directory => {
        const file = path.join(directory, 'learntokd.toml');
        fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(key, ''));
      }],
    ]) {
      const copy = path.join(tmp, name);
      fs.cpSync(backup, copy, { recursive: true });
      mutate(copy);
      reseal(copy);
      const destination = path.join(tmp, `${name}-restore`);
      const result = recover('restore', copy, destination, newDatabase);
      assert.notEqual(result.status, 0, name);
      assert(!fs.existsSync(destination));
      assert(!result.stdout.includes(sourceKey) && !result.stderr.includes(sourceKey));
      assert(!result.stdout.includes(key) && !result.stderr.includes(key));
      assert.equal(sql(newDatabase, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"), '0');
    }
    const result = recover('restore', backup, fresh, newDatabase);
    assert.equal(result.status, 0, result.stderr);
    const freshData = path.join(fresh, 'data');
    assert.equal(sql(newDatabase, "SELECT count(*) FROM account_erasure_jobs WHERE id='c13-pg-cleanup';"), '1');
    assert.equal(sql(newDatabase, "SELECT count(*) FROM account_erasure_jobs WHERE id='c13-pg-revoke';"), '1');
    assert.equal(sql(newDatabase, "SELECT count(*) FROM erased_tenants WHERE tenant_id='c13-pg-erased';"), '1');
    assert.equal(sql(newDatabase, "SELECT count(*) FROM erased_users WHERE user_id='c13-pg-erased-user';"), '1');
    assert.equal(sql(newDatabase, "SELECT count(*) FROM feedback_events WHERE event_id='c13-pg-review';"), '1');
    assert.equal(sql(newDatabase, `SELECT exposures || ',' || reps || ',' || projection_version FROM memory_states WHERE card_id='${item.card.id}';`), '1,1,1');
    assert.equal(fs.statSync(path.join(fresh, 'learntokd.toml')).mode & 0o777, 0o600);
    execFileSync('sha256sum', ['--check', '--strict', 'SHA256SUMS'], { cwd: fresh, stdio: 'pipe' });
    restored = await start(freshData, path.join(fresh, 'learntokd.toml'));
    const login = await request(restored, '/v1/auth/login', credentials);
    assert.equal(login.user.user_id, auth.user.user_id);
    await request(restored, '/v1/decks', undefined, auth.access_token);
    // 首轮受理清理后停止进程，仅推进隔离夹具中 queued 调度的测试时钟。
    // 新租约模型不会因重启重置游标或重复处理同一周期，显式跨过空页再验证重扫。
    assert.equal(sql(newDatabase, "SELECT e.progress || ',' || j.state || ',' || e.assets_ack FROM account_erasure_jobs e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id WHERE e.id='c13-pg-cleanup';"), 'complete,succeeded,1');
    await stop(restored);
    restored = undefined;
    for (let cycle = 0; cycle < 2; cycle += 1) {
      sql(newDatabase, "UPDATE background_jobs SET available_at_ms=0 WHERE work_scope='maintenance' AND state='queued';");
      restored = await start(freshData, path.join(fresh, 'learntokd.toml'));
      if (cycle === 0) {
        await stop(restored);
        restored = undefined;
        // 完成后的晚到写入必须由后续持久周期清理，而非只验证原始文件不存在。
        fs.mkdirSync(path.join(freshData, 'assets/tenants/c13-pg-erased'), { recursive: true });
        fs.writeFileSync(path.join(freshData, 'assets/tenants/c13-pg-erased/late.wav'), 'synthetic post-cycle late write');
      }
    }
    const cleanupDeadline = Date.now() + 20_000;
    let cleanupCompleted = false;
    while (Date.now() < cleanupDeadline) {
      const [progress, state, acknowledgement, attempts] = sql(newDatabase,
        "SELECT e.progress || ',' || j.state || ',' || e.assets_ack || ',' || e.total_attempts FROM account_erasure_jobs e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id WHERE e.id='c13-pg-cleanup';").split(',');
      if (progress === 'complete' && state === 'succeeded' && acknowledgement === '1' && Number(attempts) >= 2) {
        cleanupCompleted = true;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert(cleanupCompleted, 'restored asset cleanup and startup resweep must complete before shutdown');
    await stop(restored);
    restored = undefined;
    assert(!fs.existsSync(path.join(freshData, 'assets/tenants/c13-pg-erased/late.wav')));
    // 完成保留操作身份、最小证据和调度结果，未决撤销仍有独立的恢复责任。
    assert.equal(sql(newDatabase, "SELECT e.progress || ',' || j.state || ',' || e.assets_ack FROM account_erasure_jobs e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id WHERE e.id='c13-pg-cleanup';"), 'complete,succeeded,1');
    assert.deepEqual(JSON.parse(sql(newDatabase, "SELECT body FROM account_erasure_jobs WHERE id='c13-pg-cleanup';")), pending);
    assert.equal(sql(newDatabase, "SELECT count(*) FROM account_erasure_jobs WHERE id='c13-pg-revoke';"), '1', 'uncompleted revocation must retain durable responsibility');
    assert.deepEqual(JSON.parse(sql(newDatabase, "SELECT body FROM account_erasure_jobs WHERE id='c13-pg-revoke';")), revocation);
    // 关闭可打断正在撤销的调用；原 claim 与密文留待租约到期恢复，不要求先进入重试态。
    const revocationState = sql(newDatabase, "SELECT e.progress || ',' || j.state FROM account_erasure_jobs e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id WHERE e.id='c13-pg-revoke';");
    assert(['pending,queued', 'reconciling,running', 'blocked,queued', 'blocked,dead'].includes(revocationState),
      'unresolved revocation must retain recoverable work without completion');
    const rejected = spawnSync('psql', ['-XAt', '--set=ON_ERROR_STOP=1', '--dbname', newDatabase], {
      input: "INSERT INTO decks(id,tenant_id,title,language,created_at) VALUES('blocked','c13-pg-erased','blocked','en',now());", encoding: 'utf8',
    });
    assert.notEqual(rejected.status, 0, 'restored tombstone must reject resurrection');
    assert.match(rejected.stderr, /ERROR:  tenant missing or erased/);
    fs.writeFileSync(single, configuration(newDatabase, false));
    restored = await start(freshData, single);
    const recovered = await fetch(`${restored.url}${mediaPath}`);
    assert.equal(recovered.status, 200);
    assert.deepEqual(Buffer.from(await recovered.arrayBuffer()), media);
    const duplicate = await request(restored, '/v1/feedback', feedback);
    assert.equal(duplicate.duplicates, 1);
    assert.equal(duplicate.accepted, 0);
    const occupied = recover('restore', backup, path.join(tmp, 'occupied-db'), newDatabase);
    assert.notEqual(occupied.status, 0, 'populated database must refuse restore');
    assert.equal(sql(newDatabase, "SELECT count(*) FROM feedback_events WHERE event_id='c13-pg-review';"), '1');
    assert(!fs.existsSync(path.join(tmp, 'occupied-db')));
  } finally {
    const cleanupErrors = [];
    for (const process of [server, restored]) {
      if (process) try { await stop(process); } catch (error) { cleanupErrors.push(error); }
    }
    for (const name of owned.reverse()) {
      try {
        assert.equal(sql(admin, `SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname='${name}';`), `memoswish-c13-recovery:${process.pid}`);
        sql(admin, `DROP DATABASE "${name}";`);
      } catch (error) { cleanupErrors.push(new Error(`Owned recovery database cleanup failed: ${name}`, { cause: error })); }
    }
    fs.rmSync(tmp, { recursive: true, force: true });
    assert.deepEqual(cleanupErrors, [], 'PostgreSQL recovery fixture cleanup must complete');
  }
});
