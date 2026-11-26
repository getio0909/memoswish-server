import { execFileSync } from 'node:child_process';

for (const args of [['--test', 'processes.test.mjs'], ['qualify.mjs']]) {
  execFileSync(process.execPath, args, {stdio:'inherit'});
}
