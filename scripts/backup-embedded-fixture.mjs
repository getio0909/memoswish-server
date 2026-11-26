// 恢复演练共用真实进程、HTTP 与完整清单辅助函数。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';

export function prepareRecoveryBinary(source, destination) {
  // 摘要与版本绑定仍针对真实二进制，只移除测试副本中不参与运行的符号和调试信息。
  execFileSync('strip', ['--strip-all', '-o', destination, source], { stdio: 'pipe' });
  fs.chmodSync(destination, 0o700);
  assert.equal(execFileSync(destination, ['--version'], { encoding: 'utf8' }),
    execFileSync(source, ['--version'], { encoding: 'utf8' }));
}

export function recoveryFixture({ root, tmp, binary, environment }) {
  function reseal(directory) {
    const names = [];
    function visit(base, prefix = '') {
      for (const name of fs.readdirSync(base)) {
        const relative = prefix ? `${prefix}/${name}` : name;
        if (fs.statSync(path.join(base, name)).isDirectory()) visit(path.join(base, name), relative);
        else if (relative !== 'SHA256SUMS') names.push(relative);
      }
    }
    visit(directory);
    fs.writeFileSync(path.join(directory, 'SHA256SUMS'), names.sort().map(name =>
      `${createHash('sha256').update(fs.readFileSync(path.join(directory, name))).digest('hex')}  ${name}\n`).join(''));
  }
  async function start(data, configuration) {
    const log = path.join(tmp, `server-${path.basename(data)}.log`);
    const fd = fs.openSync(log, 'w', 0o600);
    const child = spawn(binary, ['--data-dir', data,
      '--config', configuration, '--bind', '127.0.0.1:0', 'serve'], {
      cwd: root, env: { ...environment, NO_COLOR: '1', RUST_LOG: 'info,sqlx=warn' }, stdio: ['ignore', fd, fd],
    });
    fs.closeSync(fd);
    const exited = once(child, 'exit');
    try {
      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline) {
        assert.equal(child.exitCode, null, 'server exited before readiness');
        const address = fs.readFileSync(log, 'utf8').match(/addr=(127\.0\.0\.1:\d+)/)?.[1];
        if (address) {
          const url = `http://${address}`;
          const response = await fetch(`${url}/readyz`);
          if (response.ok) return { child, exited, url };
        }
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      throw new Error('server readiness timed out');
    } catch (error) {
      child.kill('SIGTERM');
      await exited;
      throw error;
    }
  }

  async function stop(server) {
    server.child.kill('SIGTERM');
    const [code] = await server.exited;
    assert.equal(code, 0, 'server must stop and drain successfully');
  }
  async function request(server, endpoint, body, token) {
    const response = await fetch(`${server.url}${endpoint}`, {
      method: body ? 'POST' : 'GET',
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    assert.equal(response.status, 200, `${endpoint} status`);
    return response.json();
  }

  return { reseal, start, stop, request };
}
