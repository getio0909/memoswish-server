import './legacy-environment.cjs';
// 使用真实 CLI、SQLite 和 HTTP 路由，全部凭据与用户均为临时合成夹具。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { test, before, after } from 'node:test';
import { prepareRecoveryBinary, recoveryFixture } from './backup-embedded-fixture.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceBinary = path.resolve(process.env.MEMOSWISH_RECOVERY_BINARY || path.join(root, 'server/target/debug/memoswishd'));
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('MEMOSWISH_') && key !== 'DATABASE_URL'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "memoswish-recovery-' fixture-"));
// 固定本次二进制，避免同工作树 Cargo 切换 feature 时替换可执行文件干扰版本断言。
const binary = path.join(tmp, 'memoswishd');
const source = path.join(tmp, 'source');
const backup = path.join(tmp, 'backup');
const restore = path.join(tmp, 'restored');
const config = path.join(tmp, 'original.toml');
const { reseal, start, stop, request } = recoveryFixture({ root, tmp, binary, environment });

function command(program, args, options = {}) {
  return execFileSync(program, args, { cwd: root, env: environment, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], ...options });
}
function sql(data, query) {
  return command('sqlite3', ['-batch', '-bail', path.join(data, 'learntok.db')], { input: query }).trim();
}
function recover(mode, input, output, extra = []) {
  const result = spawnSync(path.join(root, 'scripts', mode === 'backup' ? 'backup-embedded' : 'restore-embedded'),
    [input, output, '--memoswishd', binary, ...extra], { cwd: root, env: environment, encoding: 'utf8' });
  assert.ifError(result.error);
  return result;
}
function damaged(name, mutate, expected) {
  const copy = path.join(tmp, name);
  fs.cpSync(backup, copy, { recursive: true });
  mutate(copy);
  const destination = path.join(tmp, `${name}-restore`);
  const result = recover('restore', copy, destination);
  assert.notEqual(result.status, 0);
  if (expected) assert.match(result.stderr, expected);
  assert(!fs.existsSync(destination));
  assert(!fs.existsSync(`${destination}.lock`));
  assert(fs.existsSync(copy));
}

before(() => {
  prepareRecoveryBinary(sourceBinary, binary);
  fs.writeFileSync(config, 'mode = "multi_tenant"\nregistration_open = true\nseed_demo = true\n[tts]\ndefault_engine = "placeholder"\nauto_detect_espeak = false\n');
  command(binary, ['--data-dir', source, '--config', config, 'seed']);
  const result = recover('backup', source, backup, ['--config', config]);
  assert.equal(result.status, 0, result.stderr);
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test('cold snapshot restores exact schema, assets, effective configuration and restrictive permissions', () => {
  const result = recover('restore', backup, restore);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(sql(path.join(restore, 'data'), 'SELECT COUNT(*) FROM cards;'), sql(source, 'SELECT COUNT(*) FROM cards;'));
  assert.equal(fs.statSync(path.join(restore, 'learntokd.toml')).mode & 0o777, 0o600);
  assert.equal(fs.statSync(restore).mode & 0o777, 0o700);
  command('sha256sum', ['--check', '--strict', 'SHA256SUMS'], { cwd: restore });
});

test('missing source key fails without generating a replacement or publishing a backup', () => {
  const missing = path.join(tmp, 'missing-key');
  fs.cpSync(source, missing, { recursive: true });
  fs.unlinkSync(path.join(missing, 'jwt_secret'));
  const target = path.join(tmp, 'missing-key-backup');
  assert.notEqual(recover('backup', missing, target, ['--config', config]).status, 0);
  assert(!fs.existsSync(path.join(missing, 'jwt_secret')));
  assert(!fs.existsSync(target));
});

test('partial files, changed bytes, missing config, unexpected files and sidecars fail closed', () => {
  damaged('partial', directory => fs.truncateSync(path.join(directory, 'data/learntok.db'), 127), /checksum/);
  damaged('changed', directory => fs.appendFileSync(path.join(directory, 'learntokd.toml'), '\n# altered\n'), /checksum/);
  damaged('missing-config', directory => fs.unlinkSync(path.join(directory, 'learntokd.toml')), /incomplete/);
  damaged('extra-file', directory => fs.writeFileSync(path.join(directory, 'data/extra'), 'unexpected'), /checksum/);
  damaged('sidecar', directory => {
    fs.writeFileSync(path.join(directory, 'data/learntok.db-wal'), 'incomplete');
    reseal(directory);
  }, /sidecar/);
});

test('unknown format, binary identity, schema version and migration checksums fail even with resealed files', () => {
  for (const [name, change] of [
    ['wrong-format', manifest => { manifest.format_version = 2; }],
    ['wrong-binary', manifest => { manifest.binary_sha256 = '0'.repeat(64); }],
    ['wrong-version', manifest => { manifest.application_version = 'memoswishd 9.0.0'; }],
    ['wrong-schema-manifest', manifest => { manifest.schema.pop(); }],
  ]) {
    damaged(name, directory => {
      const file = path.join(directory, 'manifest.json');
      const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
      change(manifest);
      fs.writeFileSync(file, JSON.stringify(manifest));
      reseal(directory);
    });
  }
  damaged('wrong-db-schema', directory => {
    sql(path.join(directory, 'data'), 'UPDATE _sqlx_migrations SET success=0 WHERE version=11;');
    reseal(directory);
  }, /unsupported schema/);
  damaged('wrong-migration-hash', directory => {
    sql(path.join(directory, 'data'), "UPDATE _sqlx_migrations SET checksum=x'00' WHERE version=1;");
    reseal(directory);
  }, /unsupported schema/);
});

test('missing effective key, remote database and missing OIDC encryption key fail before publication', () => {
  damaged('missing-effective-key', directory => {
    const file = path.join(directory, 'learntokd.toml');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(/^jwt_secret = .*$/m, 'jwt_secret = ""'));
    reseal(directory);
  });
  damaged('remote-database', directory => {
    const file = path.join(directory, 'learntokd.toml');
    fs.writeFileSync(file, `database_url = "postgres://localhost/recovery"\n${fs.readFileSync(file, 'utf8')}`);
    reseal(directory);
  });
  damaged('missing-oidc-key', directory => {
    const file = path.join(directory, 'learntokd.toml');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('[oidc]\nenabled = false', '[oidc]\nenabled = true'));
    reseal(directory);
  });
  damaged('pending-revocation-key', directory => {
    const job = { id: 'pending-oidc', tenant_id: 'erased-oidc', purge_assets: false, credentials: [['apple', 'synthetic-ciphertext']] };
    sql(path.join(directory, 'data'), `INSERT INTO account_erasure_jobs(id,body) VALUES('pending-oidc','${JSON.stringify(job)}');`);
    reseal(directory);
  });
});

test('a resealed damaged database and foreign-key violations fail integrity checks', () => {
  damaged('invalid-sqlite', directory => {
    fs.writeFileSync(path.join(directory, 'data/learntok.db'), 'synthetic broken database');
    reseal(directory);
  });
  damaged('invalid-foreign-key', directory => {
    sql(path.join(directory, 'data'), "PRAGMA foreign_keys=OFF; INSERT INTO recent_authentication(hash,tenant_id,user_id,expires_at) VALUES('broken','absent-tenant','absent-user',0);");
    reseal(directory);
  }, /foreign key/);
});

test('links, nonregular entries, hostile checksum paths and occupied destinations preserve unrelated files', () => {
  damaged('symlink', directory => fs.symlinkSync(config, path.join(directory, 'data/link')));
  damaged('fifo', directory => command('mkfifo', [path.join(directory, 'data/pipe')]));
  damaged('hostile-path', directory => fs.appendFileSync(path.join(directory, 'SHA256SUMS'), `${'0'.repeat(64)}  ../../unrelated\n`), /checksum/);
  const occupied = path.join(tmp, 'occupied');
  fs.mkdirSync(occupied);
  fs.writeFileSync(path.join(occupied, 'sentinel'), 'unrelated');
  assert.notEqual(recover('restore', backup, occupied).status, 0);
  assert.equal(fs.readFileSync(path.join(occupied, 'sentinel'), 'utf8'), 'unrelated');
  const dangling = path.join(tmp, 'dangling');
  fs.symlinkSync(path.join(tmp, 'absent'), dangling);
  assert.notEqual(recover('restore', backup, dangling).status, 0);
  assert(fs.lstatSync(dangling).isSymbolicLink());
  assert.notEqual(recover('backup', source, path.join(source, 'nested')).status, 0);
  const absent = path.join(tmp, 'absent-source');
  assert.notEqual(recover('backup', absent, path.join(tmp, 'absent-backup')).status, 0);
  assert(!fs.existsSync(absent), 'flock must not create an invalid source file');
  const sourceLink = path.join(tmp, 'source-link');
  fs.symlinkSync(source, sourceLink);
  assert.notEqual(recover('backup', sourceLink, path.join(tmp, 'linked-backup')).status, 0);
});

test('environment-injected keys are saved and restore validation ignores ambient overrides', () => {
  const output = path.join(tmp, 'environment.toml');
  const secret = 'synthetic-environment-secret-at-least-32-bytes';
  command(binary, ['--data-dir', source, 'snapshot-config', '--output', output], {
    env: { ...environment, MEMOSWISH_JWT_SECRET: secret },
  });
  assert(fs.readFileSync(output, 'utf8').includes(secret));
  const destination = path.join(tmp, 'ambient-restore');
  const result = spawnSync(path.join(root, 'scripts/restore-embedded'), [backup, destination, '--memoswishd', binary], {
    env: { ...environment, MEMOSWISH_JWT_SECRET: 'bad', MEMOSWISH_DATABASE_URL: 'postgres://localhost/wrong' }, encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert(!result.stdout.includes(secret) && !result.stderr.includes(secret));
});

test('OIDC encryption and provider secrets survive configuration capture without network calls', () => {
  const input = path.join(tmp, 'oidc.toml');
  const output = path.join(tmp, 'oidc-snapshot.toml');
  const key = 'A'.repeat(43);
  fs.writeFileSync(input, `[oidc]\nenabled = false\npublic_base_url = "https://learn.example.test"\nencryption_key = "${key}"\nreturn_uris = ["com.memoswish.app:/auth/callback"]\n[[oidc.providers]]\nid = "example"\nname = "Example"\nissuer = "https://auth.example.test"\ndiscovery_url = "https://auth.example.test/.well-known/openid-configuration"\nclient_id = "c13"\nclient_secret = "synthetic-provider-secret"\napple_private_key = "synthetic-private-key"\nallowed_hosts = ["auth.example.test"]\n`);
  command(binary, ['--data-dir', source, '--config', input, 'snapshot-config', '--require-oidc-key', '--output', output]);
  const captured = fs.readFileSync(output, 'utf8');
  for (const secret of [key, 'synthetic-provider-secret', 'synthetic-private-key']) assert(captured.includes(secret));
  fs.writeFileSync(input, fs.readFileSync(input, 'utf8').replace(key, `${'A'.repeat(42)}B`));
  const invalid = path.join(tmp, 'oidc-invalid-output.toml');
  const result = spawnSync(binary, ['--data-dir', source, '--config', input, 'snapshot-config', '--output', invalid], {
    env: environment, encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert(!fs.existsSync(invalid));
  assert(!result.stderr.includes('synthetic-provider-secret'));
});

test('concurrent restores publish one complete directory and leave the source unchanged', async () => {
  const destination = path.join(tmp, 'concurrent');
  const before = fs.readFileSync(path.join(backup, 'SHA256SUMS'), 'utf8');
  function attempt() {
    const child = spawn(path.join(root, 'scripts/restore-embedded'), [backup, destination, '--memoswishd', binary], {
      cwd: root, env: environment, stdio: 'ignore',
    });
    return once(child, 'exit').then(([code]) => code);
  }
  const results = await Promise.all([attempt(), attempt()]);
  assert.equal(results.filter(code => code === 0).length, 1);
  assert.equal(results.filter(code => code !== 0).length, 1);
  assert.equal(fs.readFileSync(path.join(backup, 'SHA256SUMS'), 'utf8'), before);
  command('sha256sum', ['--check', '--strict', 'SHA256SUMS'], { cwd: destination });
  assert(!fs.existsSync(`${destination}.lock`));
});

test('every direct writer refuses an already locked directory before startup writes', async () => {
  const data = path.join(tmp, 'locked-startup');
  fs.mkdirSync(data);
  const holder = spawn('flock', ['--exclusive', '--nonblock', data, process.execPath, '-e',
    'process.stdout.write("READY"); process.stdin.resume();'], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(holder, 'exit');
  try {
    await once(holder.stdout, 'data');
    for (const args of [[], ['serve'], ['mcp-stdio'], ['seed'], ['token', 'create', '--name', 'blocked']]) {
      const result = spawnSync(binary, ['--data-dir', data, ...args], { env: environment, encoding: 'utf8' });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /data directory is locked/);
      assert.deepEqual(fs.readdirSync(data), [], 'no migration, key, asset or seed may precede locking');
    }
  } finally {
    holder.stdin.end();
    assert.equal((await exited)[0], 0);
  }
  command(binary, ['--data-dir', data, 'seed']);
  assert(fs.existsSync(path.join(data, 'jwt_secret')), 'lock releases with holder exit');
});

test('MCP stdio owns the native lock for its lifetime and restore refuses a live backup data directory', async () => {
  const data = path.join(tmp, 'mcp');
  fs.cpSync(source, data, { recursive: true });
  const child = spawn(binary, ['--data-dir', data, 'mcp-stdio'], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(child, 'exit');
  try {
    await new Promise((resolve, reject) => {
      let logs = '';
      child.stderr.on('data', bytes => { logs += bytes; if (logs.includes('mcp stdio server ready')) resolve(); });
      child.on('exit', () => reject(new Error('MCP exited before readiness')));
    });
    assert.notEqual(recover('backup', data, path.join(tmp, 'mcp-blocked')).status, 0);
  } finally {
    child.stdin.end();
    assert.equal((await exited)[0], 0);
  }
  const afterEof = recover('backup', data, path.join(tmp, 'mcp-after-eof'));
  assert.equal(afterEof.status, 0, afterEof.stderr);
  const liveBackup = path.join(tmp, 'running-backup');
  fs.cpSync(backup, liveBackup, { recursive: true });
  const server = await start(path.join(liveBackup, 'data'), path.join(liveBackup, 'learntokd.toml'));
  try {
    assert.notEqual(recover('restore', liveBackup, path.join(tmp, 'restore-blocked')).status, 0);
    assert(!fs.existsSync(path.join(tmp, 'restore-blocked')));
  } finally { await stop(server); }
});
test('a real backup holds the startup barrier until publication, then direct serve can restart', async () => {
  const data = path.join(tmp, 'backup-first');
  fs.cpSync(source, data, { recursive: true });
  const shim = path.join(tmp, 'sqlite-barrier');
  fs.mkdirSync(shim);
  const ready = path.join(shim, 'ready');
  const release = path.join(shim, 'release');
  command('mkfifo', [release]);
  const sqliteBinary = command('which', ['sqlite3']).trim();
  // 仅夹具在第一次只读 SQL 调用处挂起；不引入产品计时或新的租约。
  fs.writeFileSync(path.join(shim, 'sqlite3'), `#!${process.execPath}\nconst fs=require('fs');
if (!fs.existsSync(${JSON.stringify(ready)})) {
  fs.writeFileSync(${JSON.stringify(ready)}, 'ready');
  fs.readFileSync(${JSON.stringify(release)});
}
const result=require('child_process').spawnSync(${JSON.stringify(sqliteBinary)}, process.argv.slice(2), {stdio:'inherit'});
process.exit(result.status ?? 1);
`, { mode: 0o700 });
  const destination = path.join(tmp, 'backup-first-saved');
  const child = spawn(path.join(root, 'scripts/backup-embedded'), [data, destination, '--memoswishd', binary, '--config', config], {
    env: { ...environment, PATH: `${shim}:${environment.PATH}` }, stdio: 'ignore',
  });
  const exited = once(child, 'exit');
  const watcher = fs.watch(shim);
  try {
    await new Promise((resolve, reject) => {
      if (fs.existsSync(ready)) return resolve();
      watcher.on('change', () => { if (fs.existsSync(ready)) resolve(); });
      child.on('exit', () => reject(new Error('backup exited before barrier')));
    });
    const refused = spawnSync(binary, ['--data-dir', data, 'serve'], { env: environment, encoding: 'utf8' });
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /data directory is locked/);
  } finally {
    watcher.close();
    if (child.exitCode === null && fs.existsSync(ready)) await fs.promises.writeFile(release, 'release');
    assert.equal((await exited)[0], 0, 'backup completes after barrier release');
  }
  assert(fs.existsSync(path.join(destination, 'manifest.json')));
  const server = await start(data, config);
  await stop(server);
});

test('real stop/restore preserves login, existing JWT, media, reviews, pending cleanup and tombstone fences', async () => {
  const liveData = path.join(tmp, 'live');
  fs.cpSync(source, liveData, { recursive: true });
  let server = await start(liveData, config);
  let restoredServer;
  try {
    const credentials = { email: 'c13@example.test', password: 'synthetic-password-123' };
    const auth = await request(server, '/v1/auth/register', { ...credentials, display_name: 'C13' });
    const token = auth.access_token;
    const blocked = recover('backup', liveData, path.join(tmp, 'blocked-backup'), ['--config', config]);
    assert.notEqual(blocked.status, 0, 'live directory lock must refuse backup');
    assert(!fs.existsSync(path.join(tmp, 'blocked-backup')));
    // 本地演示卡组通过单用户配置生成学习记录，多租户账户另验密码及 JWT。
    await stop(server);
    server = undefined;
    const single = path.join(tmp, 'single.toml');
    fs.writeFileSync(single, 'seed_demo = true\n[tts]\ndefault_engine = "placeholder"\nauto_detect_espeak = false\n');
    server = await start(liveData, single);
    const page = await request(server, '/v1/feed');
    const item = page.items[0];
    const feedback = {
      session_id: page.session_id, client_id: 'c13', sent_at: new Date().toISOString(),
      events: [{ event_id: 'c13-review', card_id: item.card.id, slot: item.slot,
        shown_at: new Date().toISOString(), dwell_time_ms: 3000, loop_count: 1, swipe_velocity: 1.2,
        swipe_direction: 'next', flipped: false, double_tapped: true, long_pressed: false, muted: false }],
    };
    const ack = await request(server, '/v1/feedback', feedback);
    assert.equal(ack.accepted, 1);
    const mediaPath = item.card.tts.audio.url;
    const originalMedia = Buffer.from(await (await fetch(`${server.url}${mediaPath}`)).arrayBuffer());
    assert(originalMedia.length > 44);
    await stop(server);
    server = undefined;
    // 故障退出留下已提交 WAL，证明快照不会遗漏 WAL 中的墓碑及持久清理任务。
    const sqlite = spawn('sqlite3', ['-bail', path.join(liveData, 'learntok.db')], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    const sqliteExit = once(sqlite, 'exit');
    const ready = new Promise((resolve, reject) => {
      sqlite.stdout.on('data', bytes => { if (bytes.toString().includes('READY')) resolve(); });
      sqlite.stderr.on('data', () => reject(new Error('SQLite WAL fixture failed')));
    });
    const pending = { id: 'c13-cleanup', tenant_id: 'c13-erased', purge_assets: true, credentials: [] };
    sqlite.stdin.write(`PRAGMA journal_mode=WAL;\nPRAGMA wal_autocheckpoint=0;\nINSERT INTO erased_tenants VALUES('c13-erased');\nINSERT INTO erased_users VALUES('c13-erased','c13-erased-user');\nINSERT INTO account_erasure_jobs(id,body) VALUES('c13-cleanup','${JSON.stringify(pending)}');\n.print READY\n`);
    try { await ready; } finally {
      sqlite.kill('SIGKILL');
      await sqliteExit;
    }
    assert(fs.statSync(path.join(liveData, 'learntok.db-wal')).size > 0);
    const erasedAssets = path.join(liveData, 'assets/tenants/c13-erased');
    fs.mkdirSync(erasedAssets, { recursive: true });
    fs.writeFileSync(path.join(erasedAssets, 'late.wav'), 'synthetic late write');
    const liveBackup = path.join(tmp, 'live-backup');
    const saved = recover('backup', liveData, liveBackup, ['--config', config]);
    assert.equal(saved.status, 0, saved.stderr);
    const fresh = path.join(tmp, 'fresh');
    const result = recover('restore', liveBackup, fresh);
    assert.equal(result.status, 0, result.stderr);
    const freshData = path.join(fresh, 'data');
    assert.equal(sql(freshData, "SELECT COUNT(*) FROM account_erasure_jobs WHERE id='c13-cleanup';"), '1');
    assert.equal(sql(freshData, "SELECT COUNT(*) FROM erased_tenants WHERE tenant_id='c13-erased';"), '1');
    assert.equal(sql(freshData, "SELECT COUNT(*) FROM erased_users WHERE user_id='c13-erased-user';"), '1');
    assert.equal(sql(freshData, "SELECT COUNT(*) FROM feedback_events WHERE event_id='c13-review';"), '1');
    assert.equal(sql(freshData, `SELECT exposures FROM memory_states WHERE card_id='${item.card.id}';`), '1');
    assert.equal(sql(freshData, `SELECT reps FROM memory_states WHERE card_id='${item.card.id}';`), '1');
    assert.equal(sql(freshData, `SELECT projection_version FROM memory_states WHERE card_id='${item.card.id}';`), '1');
    restoredServer = await start(freshData, path.join(fresh, 'learntokd.toml'));
    const login = await request(restoredServer, '/v1/auth/login', credentials);
    assert.equal(login.user.user_id, auth.user.user_id);
    await request(restoredServer, '/v1/decks', undefined, token);
    await stop(restoredServer);
    restoredServer = undefined;
    assert(!fs.existsSync(path.join(freshData, 'assets/tenants/c13-erased/late.wav')), 'startup cleanup must remove late erased assets');
    assert.equal(sql(freshData, "SELECT COUNT(*) FROM erased_tenants WHERE tenant_id='c13-erased';"), '1');
    const rejected = spawnSync('sqlite3', [path.join(freshData, 'learntok.db'), "INSERT INTO decks VALUES('blocked','c13-erased','blocked','','en','[]','now');"], { encoding: 'utf8' });
    assert.notEqual(rejected.status, 0, 'restored tombstone must reject resurrection');
    restoredServer = await start(freshData, single);
    const recoveredMedia = await fetch(`${restoredServer.url}${mediaPath}`);
    assert.equal(recoveredMedia.status, 200);
    assert.deepEqual(Buffer.from(await recoveredMedia.arrayBuffer()), originalMedia);
    const duplicate = await request(restoredServer, '/v1/feedback', feedback);
    assert.equal(duplicate.duplicates, 1);
    assert.equal(duplicate.accepted, 0);
  } finally {
    if (server) await stop(server);
    if (restoredServer) await stop(restoredServer);
  }
});
