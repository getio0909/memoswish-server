import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import { spawnOwned, stopOwned, waitOwned } from './processes.mjs';

test('nonterminating Inspector-style process and descendant are killed after bounded grace', async () => {
  const children = new Set();
  const source = `
    const { spawn } = require('node:child_process');
    process.on('SIGTERM', () => {});
    const child = spawn(process.execPath, ['-e', "process.on('SIGTERM', () => {}); process.send('ready'); setInterval(() => {}, 1000)"], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    child.on('message', () => process.send({ descendant: child.pid }));
    setInterval(() => {}, 1000);
  `;
  const owned = spawnOwned(children, process.execPath, ['-e', source], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] }, 'nonterminating Inspector');
  try {
    const [{ descendant }] = await Promise.race([
      once(owned.child, 'message'),
      waitOwned(owned).then(() => { throw new Error('fixture child closed before readiness'); }),
    ]);
    assert.ok(children.has(owned), 'Inspector must be in the ownership set');
    await assert.rejects(waitOwned(owned, 50), /completion budget exceeded/);
    await assert.rejects(stopOwned(owned, 100), /required SIGKILL after grace/);
    const result = await waitOwned(owned, 100);
    assert.equal(result.signal, 'SIGKILL');
    // 后代可能短暂成为等待 init 回收的僵尸，但不能继续执行。
    const { readFile } = await import('node:fs/promises');
    const state = await readFile(`/proc/${descendant}/stat`, 'utf8').catch(error => {
      if (error.code === 'ENOENT' || error.code === 'ESRCH') return null;
      throw error;
    });
    if (state) assert.equal(state.slice(state.lastIndexOf(')') + 2).split(' ')[0], 'Z');
  } finally { await stopOwned(owned, 100); }
});

test('normal exit and spawn failure settle without unhandled subprocess errors', async () => {
  const children = new Set();
  const success = spawnOwned(children, process.execPath, ['-e', 'process.stdout.write("x".repeat(80 * 1024))'], { stdio: ['ignore', 'pipe', 'pipe'] }, 'success');
  assert.equal((await waitOwned(success)).code, 0);
  assert.equal(success.output.length, 64 * 1024);
  const failure = spawnOwned(children, '/nonexistent/memoswish-fixture-command', [], { stdio: 'ignore' }, 'missing command');
  await assert.rejects(waitOwned(failure), /subprocess spawn failed/);
  await Promise.all([...children].map(child => stopOwned(child)));
});
