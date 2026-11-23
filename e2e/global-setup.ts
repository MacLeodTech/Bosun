import { type ChildProcess, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type http from 'node:http';
import { PROXY_PORT, TARGET_PORT, UI_PORT } from './ports';
import { startTarget } from './target';

const root = path.resolve(import.meta.dirname, '..');

/** Starts the target and `bosun serve`, and returns the function that stops both. */
export default async function globalSetup() {
  const bin = process.env.BOSUN_BIN ?? path.join(root, 'target', 'debug', process.platform === 'win32' ? 'bosun.exe' : 'bosun');
  if (!fs.existsSync(bin)) throw new Error(`no bosun binary at ${bin}: run \`cargo build -p bosun\` or set BOSUN_BIN`);

  const target: http.Server = await startTarget(TARGET_PORT);
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bosun-e2e-'));
  const child: ChildProcess = spawn(
    bin,
    ['serve', '--data-dir', dataDir, '--proxy', `127.0.0.1:${PROXY_PORT}`, '--listen', `127.0.0.1:${UI_PORT}`],
    { stdio: ['ignore', 'ignore', 'pipe'], env: { PATH: process.env.PATH ?? '', BOSUN_LOG: 'warn' } },
  );

  let log = '';
  const code = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`bosun did not print a setup code in 30 s:\n${log}`)), 30_000);
    child.once('exit', (c) => reject(new Error(`bosun exited early (${c}):\n${log}`)));
    child.stderr!.on('data', (d: Buffer) => {
      log += d.toString();
      const m = /setup code: (\S+)/.exec(log);
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    });
  });
  process.env.BOSUN_E2E_SETUP_CODE = code;

  return async () => {
    child.removeAllListeners('exit');
    child.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 300));
    await new Promise((r) => target.close(r));
    fs.rmSync(dataDir, { recursive: true, force: true });
  };
}
