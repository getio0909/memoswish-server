import './legacy-environment.cjs';
// 冷恢复只使用标准目录、JSON 元数据、SQLite 快照和标准 SHA256SUMS。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.umask(0o077);

class ToolError extends Error {}

function run(program, args, options = {}) {
  // 子进程错误不回显参数或 stderr，避免提供者凭据进入备份日志。
  try {
    return execFileSync(program, args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], ...options });
  } catch {
    throw new ToolError(`${path.basename(program)} failed`);
  }
}

async function digest(file, algorithm = 'sha256') {
  const hash = createHash(algorithm);
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

function files(directory, prefix = '') {
  const result = [];
  for (const name of fs.readdirSync(directory).sort()) {
    assert(!/[\\\r\n\x00-\x1f\x7f]/.test(name), 'unsupported filename');
    const relative = prefix ? `${prefix}/${name}` : name;
    const entry = fs.lstatSync(path.join(directory, name));
    assert(!entry.isSymbolicLink(), 'symbolic links are unsupported');
    if (entry.isDirectory()) result.push(...files(path.join(directory, name), relative));
    else {
      assert(entry.isFile() && entry.nlink === 1, 'only regular unlinked files are supported');
      result.push(relative);
    }
  }
  return result.sort();
}

function sqlite(database, sql) {
  return run('sqlite3', ['-batch', '-bail', '-readonly', database], { input: sql });
}

function postgres(url, sql) {
  return run('psql', ['-XAt', '--no-password', '--set=ON_ERROR_STOP=1', '--dbname', url], { input: sql }).trim();
}

function pgMajor(url) {
  const major = Math.floor(Number(postgres(url, 'SHOW server_version_num;')) / 10000);
  for (const tool of ['pg_dump', 'pg_restore']) {
    assert.equal(Number(run(tool, ['--version']).match(/\) (\d+)/)?.[1]), major, 'PostgreSQL client/server major version mismatch');
  }
  return major;
}

async function expectedSchema(profile = 'sqlite') {
  const expected = [];
  const migrations = path.join(root, 'server/crates/memoswish-storage/migrations', profile);
  for (const name of fs.readdirSync(migrations).filter(name => /^\d+_.+\.sql$/.test(name)).sort()) {
    expected.push({ version: Number(name.split('_')[0]), checksum: await digest(path.join(migrations, name), 'sha384'), success: 1 });
  }
  return expected;
}

async function schema(database, pg = false) {
  if (pg) {
    const actual = JSON.parse(postgres(database, `SELECT json_agg(m ORDER BY version) FROM
      (SELECT version, encode(checksum,'hex') AS checksum, success::int AS success FROM public._sqlx_migrations) m;`));
    assert.deepEqual(actual, await expectedSchema('postgres'), 'unsupported schema version or migration checksum');
    return actual;
  }
  assert.equal(sqlite(database, 'PRAGMA integrity_check;').trim(), 'ok', 'database integrity check failed');
  assert.equal(sqlite(database, 'PRAGMA foreign_key_check;').trim(), '', 'database foreign key check failed');
  const actual = JSON.parse(sqlite(database,
    'SELECT json_group_array(json_object(\'version\',version,\'checksum\',lower(hex(checksum)),\'success\',success)) FROM (SELECT * FROM _sqlx_migrations ORDER BY version);'));
  assert.deepEqual(actual, await expectedSchema(), 'unsupported schema version or migration checksum');
  return actual;
}

function cleanEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('MEMOSWISH_') && name !== 'DATABASE_URL'));
}

function exists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function needsOidcKey(database, pg) {
  if (pg) return postgres(database, `SELECT (EXISTS(SELECT 1 FROM federated_identities WHERE credential IS NOT NULL)
    OR EXISTS(SELECT 1 FROM account_erasure_jobs WHERE jsonb_array_length(body::jsonb->'credentials') > 0)
    OR EXISTS(SELECT 1 FROM oidc_attempts) OR EXISTS(SELECT 1 FROM oidc_handoffs))::int;`) === '1';
  return sqlite(database, `SELECT
    EXISTS(SELECT 1 FROM federated_identities WHERE credential IS NOT NULL)
    OR EXISTS(SELECT 1 FROM account_erasure_jobs WHERE json_array_length(body,'$.credentials') > 0)
    OR EXISTS(SELECT 1 FROM oidc_attempts) OR EXISTS(SELECT 1 FROM oidc_handoffs);`).trim() === '1';
}

function snapshotConfig(binary, data, output, config, environment, databaseUrl, requireOidcKey) {
  const args = ['--data-dir', data];
  if (config) args.push('--config', config);
  if (databaseUrl) args.push('--database-url', databaseUrl);
  args.push('snapshot-config', '--output', output);
  if (databaseUrl) args.push('--postgres');
  if (requireOidcKey ?? needsOidcKey(path.join(data, 'learntok.db'), false)) args.push('--require-oidc-key');
  run(binary, args, { env: environment });
}

function copy(source, destination, names) {
  for (const name of names) {
    fs.mkdirSync(path.dirname(path.join(destination, name)), { recursive: true, mode: 0o700 });
    fs.copyFileSync(path.join(source, name), path.join(destination, name), fs.constants.COPYFILE_EXCL);
    fs.chmodSync(path.join(destination, name), 0o600);
  }
}

function syncPath(file) {
  const descriptor = fs.openSync(file, 'r');
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function syncTree(directory) {
  // 发布前同步普通文件和目录，未通过完整验证的 staging 不会发布。
  for (const name of fs.readdirSync(directory)) {
    const file = path.join(directory, name);
    if (fs.statSync(file).isDirectory()) syncTree(file);
    else syncPath(file);
  }
  syncPath(directory);
}

async function checksums(directory) {
  const lines = [];
  for (const name of files(directory).filter(name => name !== 'SHA256SUMS')) {
    lines.push(`${await digest(path.join(directory, name))}  ${name}\n`);
  }
  return lines.join('');
}

async function verify(directory, binary, pg = false) {
  // 先扫描文件类型，再读取清单，阻止链接和越界路径参与任何校验或恢复。
  const names = files(directory);
  assert(names.includes('SHA256SUMS') && names.includes('manifest.json') && names.includes('learntokd.toml')
    && names.includes(pg ? 'database.dump' : 'data/learntok.db'), 'incomplete backup');
  assert.equal(fs.readFileSync(path.join(directory, 'SHA256SUMS'), 'utf8'), await checksums(directory), 'checksum or file inventory mismatch');
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8'));
  assert.equal(manifest.format_version, 1, 'unsupported backup format');
  assert.equal(manifest.profile ?? 'sqlite', pg ? 'postgres' : 'sqlite', 'wrong backup profile');
  assert.equal(manifest.binary_sha256, await digest(binary), 'wrong memoswishd binary version');
  assert.equal(manifest.application_version, run(binary, ['--version']).trim(), 'wrong application version');
  if (pg) {
    assert.deepEqual(manifest.schema, await expectedSchema('postgres'), 'schema manifest mismatch');
    assert.equal(typeof manifest.requires_oidc_key, 'boolean', 'missing encryption key requirement');
    const descriptor = fs.openSync(path.join(directory, 'database.dump'), 'r');
    const magic = Buffer.alloc(5);
    try { fs.readSync(descriptor, magic, 0, 5, 0); } finally { fs.closeSync(descriptor); }
    assert.equal(magic.toString(), 'PGDMP', 'not a custom PostgreSQL archive');
  } else assert.deepEqual(manifest.schema, await schema(path.join(directory, 'data/learntok.db')), 'schema manifest mismatch');
  assert(fs.statSync(path.join(directory, 'data/assets')).isDirectory(), 'missing local asset store');
  assert(!names.some(name => /^data\/learntok\.db-(wal|shm|journal)$/.test(name)), 'unexpected SQLite sidecar');
  return manifest;
}

async function main() {
  const [mode, sourceArg, destinationArg, ...args] = process.argv.slice(2);
  assert(['backup', 'restore'].includes(mode) && sourceArg && destinationArg,
    'Usage: backup-embedded DATA_DIR NEW_BACKUP_DIR --memoswishd BINARY [--config TOML] [--database-url POSTGRES_URL] / restore-embedded BACKUP_DIR NEW_INSTALL_DIR --memoswishd BINARY [--database-url FRESH_POSTGRES_URL]');
  let binary;
  let config;
  let databaseUrl;
  for (let i = 0; i < args.length; i += 2) {
    assert(args[i + 1], 'missing option value');
    if (args[i] === '--memoswishd' && !binary) binary = fs.realpathSync(args[i + 1]);
    else if (args[i] === '--config' && !config && mode === 'backup') config = fs.realpathSync(args[i + 1]);
    else if (args[i] === '--database-url' && !databaseUrl) databaseUrl = args[i + 1];
    else throw new Error('unknown or duplicate option');
  }
  assert(binary, 'missing --memoswishd');
  const pg = Boolean(databaseUrl);
  if (pg) assert(/^postgres(?:ql)?:\/\//.test(databaseUrl), 'expected PostgreSQL URL');
  assert(!fs.lstatSync(sourceArg).isSymbolicLink(), 'source must not be a symbolic link');
  const source = fs.realpathSync(sourceArg);
  const destination = path.join(fs.realpathSync(path.dirname(path.resolve(destinationArg))), path.basename(destinationArg));
  assert(!exists(destination), 'destination must not exist');
  assert(destination !== source && !destination.startsWith(`${source}/`), 'destination must be outside source');
  if (mode === 'backup') {
    if (!pg) assert(fs.statSync(path.join(source, 'learntok.db')).isFile(), 'missing database');
    assert(fs.statSync(path.join(source, 'assets')).isDirectory(), 'missing local asset store');
  }
  // mkdir 是目标预留，失败时不会删除已有路径。半成品仅留在私有 staging 中。
  const reservation = `${destination}.lock`;
  fs.mkdirSync(reservation, { mode: 0o700 });
  let staging;
  try {
    staging = fs.mkdtempSync(path.join(path.dirname(destination), '.memoswish-recovery-'));
    if (mode === 'backup') {
      const names = files(source).filter(name => !/^learntok\.db(?:-(?:wal|shm|journal))?$/.test(name));
      fs.mkdirSync(path.join(staging, 'data/assets'), { recursive: true, mode: 0o700 });
      copy(source, path.join(staging, 'data'), names);
      const database = pg ? databaseUrl : path.join(staging, 'data/learntok.db');
      const requiresOidcKey = needsOidcKey(pg ? databaseUrl : path.join(source, 'learntok.db'), pg);
      snapshotConfig(binary, source, path.join(staging, 'learntokd.toml'), config, process.env, databaseUrl, requiresOidcKey);
      // SQLite 参数使用 SQL 字面量转义，外部工具从不经过 shell。
      const major = pg ? pgMajor(databaseUrl) : undefined;
      if (pg) run('pg_dump', ['--no-password', '--format=custom', '--no-owner', '--no-acl', '--dbname', databaseUrl, '--file', path.join(staging, 'database.dump')]);
      else sqlite(path.join(source, 'learntok.db'), `VACUUM INTO '${database.replaceAll("'", "''")}';`);
      const manifest = {
        format_version: 1,
        application_version: run(binary, ['--version']).trim(),
        binary_sha256: await digest(binary),
        schema: await schema(database, pg),
        ...(pg ? { profile: 'postgres', postgres_major: major, requires_oidc_key: requiresOidcKey } : {}),
        created_at: new Date().toISOString(),
      };
      fs.writeFileSync(path.join(staging, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
      fs.writeFileSync(path.join(staging, 'SHA256SUMS'), await checksums(staging), { flag: 'wx', mode: 0o600 });
    } else {
      await verify(source, binary, pg);
      copy(source, staging, files(source));
      fs.mkdirSync(path.join(staging, 'data/assets'), { recursive: true, mode: 0o700 });
    }
    const manifest = await verify(staging, binary, pg);
    // 清除当前 shell 的开发覆盖值，独立验证将要恢复的有效配置与密钥。
    const validation = path.join(staging, '.config-validation.toml');
    snapshotConfig(binary, path.join(staging, 'data'), validation, path.join(staging, 'learntokd.toml'), cleanEnvironment(), databaseUrl, pg ? manifest.requires_oidc_key : undefined);
    if (pg && mode === 'restore') {
      assert.equal(pgMajor(databaseUrl), manifest.postgres_major, 'wrong PostgreSQL server version');
      // 只接受专用空数据库；禁止在已有安装上覆盖或清理表。
      assert.equal(postgres(databaseUrl, `SELECT
        (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%') +
        (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname NOT IN ('pg_catalog','information_schema')) +
        (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
          WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%') +
        (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%') +
        (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql');`), '0', 'restore requires an empty database');
      run('pg_restore', ['--no-password', '--single-transaction', '--exit-on-error', '--no-owner', '--no-acl', '--dbname', databaseUrl, path.join(staging, 'database.dump')]);
      assert.deepEqual(await schema(databaseUrl, true), manifest.schema, 'restored schema mismatch');
      fs.unlinkSync(validation);
      snapshotConfig(binary, path.join(staging, 'data'), validation, path.join(staging, 'learntokd.toml'), cleanEnvironment(), databaseUrl, needsOidcKey(databaseUrl, true));
    }
    if (pg && mode === 'restore') {
      // 只在已恢复的私有安装中绑定新数据库，保留原始备份不变。
      fs.renameSync(validation, path.join(staging, 'learntokd.toml'));
      fs.writeFileSync(path.join(staging, 'SHA256SUMS'), await checksums(staging));
    } else fs.unlinkSync(validation);
    syncTree(staging);
    // GNU mv 的 no-clobber 保护在预留锁之外出现的目标，不能覆盖别人的空目录。
    run('mv', ['--no-clobber', '--no-target-directory', '--', staging, destination]);
    assert(!exists(staging), 'destination appeared during operation');
    staging = undefined;
    syncPath(path.dirname(destination));
  } finally {
    if (staging) fs.rmSync(staging, { recursive: true, force: true });
    fs.rmdirSync(reservation);
  }
  console.log(mode === 'backup' ? 'PASS cold installation backup.' : 'PASS isolated installation restore. Keep offline until deletion and revocation reconciliation.');
}

main().catch(error => {
  // 断言对象、配置和子进程输出可能包含私密值，只输出固定消息。
  console.error(`Embedded recovery failed: ${error instanceof assert.AssertionError || error instanceof ToolError ? error.message.split('\n')[0] : 'operation failed'}`);
  process.exitCode = 1;
});
