/**
 * Smoke tests for the two user-facing installer entry points.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '..');
const run = (script: string, args: string[] = []) =>
  spawnSync('bash', [path.join(ROOT, script), ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, VAIVAR_SHOW_TOKEN: '0' },
  });

describe('installer entry points', () => {
  it('Central installer advertises the guided port flow and four checks', () => {
    const result = run('install.sh', ['--help']);
    expect(result.status).toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain('--port PORT');

    const source = readFileSync(path.join(ROOT, 'install.sh'), 'utf8');
    expect((source.match(/\[[1-4]\/4\]/g) ?? []).length).toBe(4);
  });

  it('Honeypot installer exposes the remote deployment help', () => {
    const result = run('honeypot-install.sh', ['--help']);
    expect(result.status).toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain('Pregunta por puertos');
  });

  it('Central installer rejects an invalid port before any deployment', () => {
    const result = run('install.sh', ['--port', 'not-a-port', '--configure-only']);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain('puerto');
  });
});
