import assert from 'node:assert/strict';
import { check as checkFuzzPolicy } from './fuzz-policy-check.mjs';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const json = path => JSON.parse(readFileSync(path, 'utf8'));
const nonempty = value => typeof value === 'string' && value.trim().length > 0;

export function validateToolPins(pins) {
  assert.equal(pins.schema_version, 1, 'Unknown tool pin schema');
  assert.equal(pins.platform, `${process.platform}-${process.arch}`, 'Coverage gap: unsupported pinned tool platform');
  assert.deepEqual(pins.tools.map(tool => tool.name).sort(), ['cargo-cyclonedx', 'osv-scanner'], 'Missing or unknown pinned scanner');
  for (const tool of pins.tools) {
    assert(/^[a-f0-9]{64}$/.test(tool.sha256), 'Invalid pinned tool checksum');
    assert(nonempty(tool.version) && nonempty(tool.version_line) && tool.version_line.endsWith(` ${tool.version}`), 'Invalid pinned tool version');
    assert(['binary', 'tar.xz'].includes(tool.format), 'Unknown pinned archive format');
  }
  return pins.tools;
}

export const toolPins = () => validateToolPins(json(join(root, 'scripts/supply-chain-tools.json')));

function instant(value) {
  assert(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value), 'Expected absolute UTC timestamp');
  const date = new Date(value);
  assert(Number.isFinite(+date) && date.toISOString() === value.replace('Z', '.000Z'), 'Invalid UTC timestamp');
  return +date;
}

export function validateLedger(ledger, plan, now = Date.now(), metadata) {
  assert.equal(ledger.schema_version, 1, 'Unknown exception schema');
  assert(Number.isFinite(now), 'Invalid policy clock');
  assert(Array.isArray(ledger.exceptions), 'Missing exception entries');
  const open = plan === undefined ? null : new Set([...plan.matchAll(/^- \[ \] \*\*([\w.-]+)\*\*/gm)].map(m => m[1]));
  if (open === null || ledger.owners !== undefined) {
    assert(ledger.owners && typeof ledger.owners === 'object' && !Array.isArray(ledger.owners), 'Missing exception owner status');
  }
  const ids = new Set();
  const licenseScopes = new Set();
  for (const entry of ledger.exceptions) {
    assert(nonempty(entry.id) && !ids.has(entry.id), 'Missing or duplicate exception ID');
    ids.add(entry.id);
    assert(['advisory', 'license'].includes(entry.kind), 'Unknown exception kind');
    assert(nonempty(entry.owner) && (open === null || open.has(entry.owner)) &&
      (ledger.owners === undefined || ledger.owners[entry.owner] === 'open'), `Exception owner must be an open plan row: ${entry.owner}`);
    for (const field of ['reason', 'exposure', 'mitigation', 'upstream', 'removal']) assert(nonempty(entry[field]), `Missing exception ${field}`);
    assert.equal(entry.ecosystem, 'cargo', 'Unsupported exception ecosystem');
    const { name, version, source } = entry.component ?? {};
    assert(/^[a-zA-Z0-9_-]+$/.test(name ?? '') && /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(version ?? ''), 'Exception requires exact component/version');
    assert.equal(source, 'registry+https://github.com/rust-lang/crates.io-index', 'Unreviewed exception source');
    assert.deepEqual(entry.profiles, ['repository-all-features-all-targets'], 'Unreviewed exception profiles');
    assert(Array.isArray(entry.parents) && entry.parents.length > 0 && entry.parents.every(nonempty), 'Missing dependency path scope');
    if (entry.kind === 'advisory') {
      assert(/^RUSTSEC-\d{4}-\d{4}$/.test(entry.id), 'Invalid advisory ID');
      assert(Array.isArray(entry.aliases) && entry.aliases.every(nonempty), 'Invalid advisory aliases');
    } else {
      const reviewed = name === 'libfuzzer-sys' && version === '0.4.13' ? ['NCSA'] : ['BSL-1.0'];
      assert.deepEqual(entry.allow, reviewed, 'Unreviewed license exception');
      const scope = `${name}@${version}/${source}`;
      assert(!licenseScopes.has(scope), 'Duplicate license exception scope');
      licenseScopes.add(scope);
    }
    const created = instant(entry.created_at);
    const expires = instant(entry.expires_at);
    const reviewed = instant(entry.review?.at);
    assert(nonempty(entry.review?.by) && nonempty(entry.review?.evidence), 'Renewal requires reviewed evidence');
    assert(created <= reviewed && reviewed <= now && created < expires, 'Invalid exception review window');
    assert.equal(entry.expires_at, `${entry.review_by}T00:00:00Z`, 'Review deadline must equal exclusive UTC expiry');
    assert(expires - reviewed <= 31 * 86400000, 'Exception exceeds reviewed 31-day window');
    assert(now < expires, `Expired exception: ${entry.id}`);
    if (metadata) {
      const packages = metadata.packages.filter(p => p.name === name);
      assert.equal(packages.length, 1, `Missing or expanded exception component: ${name}`);
      const pkg = packages[0];
      assert(pkg.version === version && pkg.source === source, `Exception component scope drift: ${name}`);
      const parents = metadata.resolve.nodes.filter(n => n.deps.some(d => d.pkg === pkg.id))
        .map(n => metadata.packages.find(p => p.id === n.id)?.name).sort();
      assert.deepEqual(parents, [...entry.parents].sort(), `Exception dependency path drift: ${name}`);
    }
  }
}

// 只读取 Cargo 生成的 v4 锁图。精简 checkout 缺少工作区成员，无法运行 cargo metadata。
function lockedGraph(bytes) {
  const [header, ...blocks] = bytes.replaceAll('\r\n', '\n').split('\n[[package]]\n');
  assert(/^(?:#[^\n]*\n)*version = 4\n\s*$/.test(header) && blocks.length, 'Expected canonical Cargo.lock v4');
  const packages = [];
  const refs = new Map();
  const dependencies = new Map();
  for (const block of blocks) {
    const fields = /^name = "([\w-]+)"\nversion = "([\w.+-]+)"(?:\nsource = "([^"\s\\]+)")?(?:\nchecksum = "[a-f0-9]{64}")?(?:\ndependencies = \[\n((?: "[^"\n\\]+",\n)*)\])?\n*$/.exec(block);
    assert(fields, 'Unsupported Cargo.lock package record');
    const [, name, version, source, deps = ''] = fields;
    const id = source ? `${name} ${version} (${source})` : `${name} ${version}`;
    assert(!dependencies.has(id), `Duplicate locked package: ${id}`);
    packages.push({ name, version, source, id });
    dependencies.set(id, [...deps.matchAll(/"([^"]+)"/g)].map(match => match[1]));
    for (const ref of new Set([name, `${name} ${version}`, id])) {
      if (!refs.has(ref)) refs.set(ref, []);
      refs.get(ref).push(id);
    }
  }
  const nodes = packages.map(({ id }) => ({ id, deps: dependencies.get(id).map(ref => {
    const matches = refs.get(ref);
    assert(matches?.length === 1, `Unknown or ambiguous Cargo.lock dependency: ${ref}`);
    return { pkg: matches[0] };
  }) }));
  return { packages, resolve: { nodes } };
}

// 仅序列化结构化策略，不解析 TOML；suppression 只能由台账注入。
export function renderDeny(config, ledger) {
  const fields = {
    graph: ['all-features'], advisories: ['version', 'yanked', 'unmaintained'],
    licenses: ['version', 'confidence-threshold', 'allow', 'unused-allowed-license'],
    bans: ['multiple-versions', 'wildcards', 'highlight', 'deny'],
    sources: ['unknown-registry', 'unknown-git', 'allow-registry', 'allow-git'],
  };
  assert.deepEqual(Object.keys(config).sort(), Object.keys(fields).sort(), 'Unknown deny policy section');
  for (const [section, keys] of Object.entries(fields)) {
    assert.deepEqual(Object.keys(config[section]).sort(), [...keys].sort(), 'Unknown deny policy key or unregistered suppression');
  }
  const value = item => {
    if (Array.isArray(item)) return `[${item.map(value).join(', ')}]`;
    if (item && typeof item === 'object') {
      return `{ ${Object.entries(item).map(([key, val]) => {
        assert(/^[a-z-]+$/.test(key), 'Invalid inline policy key');
        return `${key} = ${value(val)}`;
      }).join(', ')} }`;
    }
    assert(['string', 'boolean', 'number'].includes(typeof item), 'Unsupported policy value');
    return JSON.stringify(item);
  };
  const advisories = ledger.exceptions.filter(e => e.kind === 'advisory').map(e =>
    `  { id = ${JSON.stringify(e.id)}, reason = ${JSON.stringify(e.reason)} },`).join('\n');
  const licenses = ledger.exceptions.filter(e => e.kind === 'license').map(e =>
    `[[licenses.exceptions]]\nname = ${JSON.stringify(e.component.name)}\nversion = ${JSON.stringify(`=${e.component.version}`)}\nallow = ${JSON.stringify(e.allow)}`).join('\n\n');
  return '# 由 make licenses-generate 结合 JSON 策略与结构化台账生成，禁止手改。\n' + Object.entries(config).map(([section, settings]) =>
    `[${section}]\n${Object.entries(settings).map(([key, val]) => `${key} = ${value(val)}`).join('\n')}`
    + (section === 'advisories' ? `\nignore = [\n${advisories}\n]` : '')
    + (section === 'licenses' && licenses ? `\n\n${licenses}` : '')).join('\n\n') + '\n';
}

export function validateDeny(actual, expected) {
  assert.equal(actual, expected, 'Unregistered deny suppression or policy drift; run make licenses-generate and review');
}

export function checkLedger(directory = root, now = Date.now()) {
  const ledger = json(join(directory, 'supply-chain/exceptions.json'));
  const config = json(join(directory, 'scripts/supply-chain-deny-policy.json'));
  validateLedger(ledger, undefined, now, lockedGraph(readFileSync(join(directory, 'server/Cargo.lock'), 'utf8')));
  validateDeny(readFileSync(join(directory, 'deny.toml'), 'utf8'), renderDeny(config, ledger));
}

export function policy(write = false) {
  checkFuzzPolicy();
  const ledger = json(join(root, 'supply-chain/exceptions.json'));
  const plan = ['remediation-plan.md', 'phase3.md', 'cluster.md'].map(p => readFileSync(join(root, 'docs/plan', p), 'utf8')).join('\n');
  assert(ledger.owners !== undefined, 'Missing exception owner status');
  const graph = lockedGraph(readFileSync(join(root, 'server/Cargo.lock'), 'utf8'));
  validateLedger(ledger, plan, Date.now(), graph);
  const expected = renderDeny(json(join(root, 'scripts/supply-chain-deny-policy.json')), ledger);
  if (write) writeFileSync(join(root, 'deny.toml'), expected);
  else validateDeny(readFileSync(join(root, 'deny.toml'), 'utf8'), expected);
  return { ledger, plan };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, ...extra] = process.argv.slice(2);
  assert(!extra.length && [undefined, '--write-deny', '--ledger-only'].includes(mode), 'Unknown policy argument');
  if (mode === '--ledger-only') checkLedger();
  else policy(mode === '--write-deny');
  console.log('PASS structured exception policy and deny configuration');
}
