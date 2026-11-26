import { spawn } from 'node:child_process';

// 仅供夹具使用：完成预算和终止宽限分别约束等待，不参与业务状态模型。
const completionMs = 20_000;
const graceMs = 2_000;

async function within(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise(resolve => {
      timer = setTimeout(() => resolve(null), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

export function spawnOwned(children, command, args, options, label) {
  // 独立进程组让 Inspector 及其启动的 stdio 服务端共享夹具回收责任。
  const child = spawn(command, args, { ...options, detached: true });
  const owned = { child, label, output: Buffer.alloc(0) };
  owned.closed = new Promise(resolve => {
    let spawnFailed = false;
    child.once('error', () => { spawnFailed = true; });
    child.once('close', (code, signal) => resolve({ code, signal, spawnFailed }));
  });
  for (const stream of [child.stdout, child.stderr]) {
    stream?.on('data', bytes => {
      if (owned.output.length < 64 * 1024) {
        owned.output = Buffer.concat([owned.output, bytes], Math.min(64 * 1024, owned.output.length + bytes.length));
      }
    });
  }
  children.add(owned);
  return owned;
}

export async function waitOwned(owned, budget = completionMs) {
  const result = await within(owned.closed, budget);
  if (!result) throw new Error(`${owned.label}: subprocess completion budget exceeded`);
  if (result.spawnFailed) throw new Error(`${owned.label}: subprocess spawn failed`);
  return result;
}

export async function stopOwned(owned, grace = graceMs) {
  if (await within(owned.closed, 0)) return;
  const signal = name => {
    if (!owned.child.pid) return;
    try { process.kill(-owned.child.pid, name); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  };
  signal('SIGTERM');
  if (await within(owned.closed, grace)) return;
  signal('SIGKILL');
  if (await within(owned.closed, grace)) throw new Error(`${owned.label}: subprocess required SIGKILL after grace`);
  // 即使操作系统未确认回收，夹具也必须失败并解除本地句柄等待。
  for (const stream of [owned.child.stdin, owned.child.stdout, owned.child.stderr]) stream?.destroy();
  owned.child.unref();
  throw new Error(`${owned.label}: subprocess did not close after SIGKILL`);
}
