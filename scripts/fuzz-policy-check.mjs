import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const read = path => readFileSync(`${root}/${path}`, 'utf8');
export function validate(policy, graph, graphBytes, manifest, lock) {
  assert.equal(policy.schema_version, 1);
  assert.equal(policy.owner, 'P3.11');
  assert.equal(policy.cargo_fuzz, '0.13.2');
  assert.equal(policy.nightly, 'nightly-2026-08-01');
  assert.equal(policy.rustc, 'rustc 1.99.0-nightly (ad3d0bc14 2026-07-31)');
  assert.deepEqual(policy.runtime, { name: 'libfuzzer-sys', version: '0.4.13', license: '(MIT OR Apache-2.0) AND NCSA', graph: 'server/Cargo.lock' });
  assert.equal(policy.tool_graph_sha256, createHash('sha256').update(graphBytes).digest('hex'));
  assert.equal(graph.tool, 'cargo-fuzz@0.13.2');
  assert.equal(graph.platform, 'x86_64-unknown-linux-gnu');
  assert.match(graph.published_lock_sha256, /^[a-f0-9]{64}$/);
  assert.equal(graph.packages.filter(p => p.name === 'cargo-fuzz' && p.version === policy.cargo_fuzz).length, 1);
  for (const p of graph.packages) {
    assert.match(p.checksum, /^[a-f0-9]{64}$/);
    assert.equal(p.source, 'crates.io');
    assert(typeof p.license === 'string' && p.license.length > 0);
    for (const edge of p.dependencies) assert(graph.packages.some(q => `${q.name}@${q.version}` === edge));
  }
  assert.match(manifest, /libfuzzer-sys = "=0\.4\.13"/);
  assert.match(lock, /name = "libfuzzer-sys"\nversion = "0\.4\.13"/);
  assert.equal(policy.seconds_per_target, 30);
  assert.equal(policy.seed, 3909);
  assert.equal(policy.rss_limit_mb, 1024);
  assert.deepEqual(policy.targets, [
    { name: 'apkg', max_len: 10485760, timeout: 10 },
    { name: 'cloze', max_len: 262144, timeout: 2 },
    { name: 'wav', max_len: 10485760, timeout: 10 },
    { name: 'timestamp', max_len: 65536, timeout: 2 },
    { name: 'json', max_len: 262144, timeout: 10 },
  ]);
}
export function check() {
  const bytes = read('docs/licensing/fuzz-tool-graph.json');
  const policy = JSON.parse(read('scripts/fuzz-policy.json'));
  validate(policy, JSON.parse(bytes), bytes, read('server/fuzz/Cargo.toml'), read('server/Cargo.lock'));
  assert(!existsSync(`${root}/server/fuzz/Cargo.lock`), 'Fuzz must use the registered server lock graph');
  for (const target of policy.targets) {
    assert(existsSync(`${root}/server/fuzz/fuzz_targets/${target.name}.rs`));
    assert(readdirSync(`${root}/server/fuzz/corpus/${target.name}`).length > 0, 'Missing seeded corpus');
  }
  console.log('PASS exact fuzz tool/runtime graph, pins and bounded targets');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) check();
