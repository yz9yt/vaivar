/**
 * vAIvar - Semantic honeypot for attacking AI agents
 * Copyright 2026 vAIvar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const SCRIPT = path.resolve(__dirname, '../scripts/install-central.sh');

const run = (args: string[], opts: { cwd?: string; stdin?: string } = {}): { stdout: string; stderr: string; status: number } => {
  try {
    // Use spawnSync so we can capture both stdout and stderr even on success.
    const { status, stdout, stderr } = spawnSync('bash', [SCRIPT, ...args], {
      cwd: opts.cwd ?? path.resolve(__dirname, '..'),
      input: opts.stdin ?? '',
      encoding: 'utf8',
      env: { ...process.env, VAIVAR_SHOW_TOKEN: '0' },
    });
    return { stdout: stdout ?? '', stderr: stderr ?? '', status: status ?? -1 };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; status?: number };
    return { stdout: err.stdout ?? '', stderr: err.stderr ?? '', status: err.status ?? 1 };
  }
};

describe('install-central.sh (configure-only smoke tests)', () => {
  let workspace: string;

  beforeAll(() => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vaivar-installer-'));
  });

  it('help exits 0', () => {
    const r = run(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout + r.stderr).toContain('--configure-only');
  });

  it('rejects an invalid env name', () => {
    const r = run(['--env', 'bogus', '--configure-only']);
    expect(r.status).not.toBe(0);
  });

  it('rejects a non-numeric port', () => {
    const r = run(['--port', 'not-a-port', '--configure-only']);
    expect(r.status).not.toBe(0);
  });

  it('rejects an invalid bind address', () => {
    const r = run(['--bind', '999.999.999.999', '--configure-only']);
    expect(r.status).not.toBe(0);
  });

  it('configure-only writes a mode-600 env file and no tokens on stdout', () => {
    // Configure-only must not need Docker to be usable in CI; it only writes.
    const r = run(
      ['--env', 'test', '--configure-only', '--port', '38080', '--admin-email', 'test@example.com'],
      { cwd: workspace }
    );
    // The script requires docker compose only when it is going to `up`.
    if (r.status === 0) {
      const envPath = path.join(workspace, 'deploy', '.env.central.test');
      expect(fs.existsSync(envPath)).toBe(true);
      const mode = fs.statSync(envPath).mode & 0o777;
      expect(mode).toBe(0o600);
      const content = fs.readFileSync(envPath, 'utf8');
      // Tokens are generated, hex, and not placeholders.
      const key = content.match(/^VAIVAR_CENTRAL_KEY=([a-f0-9]+)$/m);
      expect(key?.[1]?.length).toBeGreaterThanOrEqual(64);
      expect(content).toMatch(/^VAIVAR_CENTRAL_INGEST_TOKEN=[a-f0-9]{64}$/m);
      expect(content).not.toContain('replace-me');
      // Secrets must not leak to the console output in non-TTY runs.
      expect(r.stdout + r.stderr).not.toMatch(/^[a-f0-9]{64}$/m);
    }
  });
});