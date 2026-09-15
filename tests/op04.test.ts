import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bootstrap, type VaivarApp } from '../src/app/bootstrap';

const TOKEN = 'deployment-test-token-0123456789abcdef';

const unusedPort = async (): Promise<number> => {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
};

describe('node control API', () => {
  let app: VaivarApp | undefined;
  let directory: string;
  let api: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'vaivar-control-'));
    for (const name of ['VAIVAR_CENTRAL_URL', 'VAIVAR_CENTRAL_INGEST_TOKEN', 'VAIVAR_SITE_ID', 'OPENCTI_URL', 'OPENCTI_TOKEN']) {
      vi.stubEnv(name, '');
    }
  });

  afterEach(async () => {
    await app?.stop();
    app = undefined;
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    rmSync(directory, { recursive: true, force: true });
  });

  const start = async () => {
    const http = await unusedPort();
    let honeypot = await unusedPort();
    while (honeypot === http) honeypot = await unusedPort();
    let restarted = false;
    const result = await bootstrap({
      masterSecret: 'a'.repeat(64),
      apiToken: TOKEN,
      ports: { http, honeypot },
      skins: ['http', 'mcp'],
      dbPath: join(directory, 'vaivar.db'),
      flushIntervalMs: 60_000,
      onRestart: async () => {
        restarted = true;
      },
      onRotateChallenges: (newGen: number) => {
        // noop: lifecycle hook captured by the API response.
      },
    });
    if (!result.ok) throw result.error;
    app = result.value;
    await app.start();
    api = `http://127.0.0.1:${http}`;
  };

  const authorized = (url: string, options: RequestInit = {}) => fetch(url, {
    ...options, headers: { Authorization: `Bearer ${TOKEN}`, ...options.headers },
  });

  test('GET /api/events returns paginated envelope when authorized', async () => {
    await start();
    // No sessions created yet, so the feed should be empty but well-formed.
    const resp = await authorized(`${api}/api/events`);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body).toMatchObject({
      spec: 'vaivar.sync.v1',
      site_id: expect.any(String),
      stream_id: expect.any(String),
      events: [],
      next_cursor: null,
      has_more: false,
    });
    expect(typeof body.high_watermark).toBe('string');
  });

  test('GET /api/events requires authentication', async () => {
    await start();
    const resp = await fetch(`${api}/api/events`);
    expect(resp.status).toBe(401);
  });

  test('POST /api/commands rejects duplicate command_id as non-executed', async () => {
    await start();
    const cmdId = 'test-restart-001';

    // First call executes the command.
    const first = await authorized(`${api}/api/commands`, {
      method: 'POST',
      body: JSON.stringify({ command_id: cmdId, type: 'control.restart' }),
    });
    expect(first.status).toBe(200);
    const firstBody = await first.json();
    expect(firstBody.executed).toBe(true);

    // Second call with the same command_id is a no-op (idempotent).
    const second = await authorized(`${api}/api/commands`, {
      method: 'POST',
      body: JSON.stringify({ command_id: cmdId, type: 'control.restart' }),
    });
    expect(second.status).toBe(200);
    const secondBody = await second.json();
    expect(secondBody.executed).toBe(false);
  });

  test('POST /api/commands requires command_id and type', async () => {
    await start();
    const resp = await authorized(`${api}/api/commands`, {
      method: 'POST',
      body: JSON.stringify({ type: 'control.restart' }),
    });
    expect(resp.status).toBe(400);
  });

  test('POST /api/control/restart returns queued outcome', async () => {
    await start();
    const cmdId = `restart_${Date.now().toString(36)}`;
    const resp = await authorized(`${api}/api/control/restart`, {
      method: 'POST',
      body: JSON.stringify({ command_id: cmdId }),
    });
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.command_id).toBe(cmdId);
    expect(body.type).toBe('control.restart');
    expect(body.executed).toBe(true);
  });

  test('POST /api/control/rotate_challenges increments generation', async () => {
    await start();
    const before = await authorized(`${api}/api/node/info`);
    const beforeBody = await before.json();
    const beforeGen = beforeBody.challenge_generation;

    const cmdId = `rotate_${Date.now().toString(36)}`;
    const resp = await authorized(`${api}/api/control/rotate_challenges`, {
      method: 'POST',
      body: JSON.stringify({ command_id: cmdId }),
    });
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.challenge_generation).toBe(beforeGen + 1);

    // Verify the new generation is persisted.
    const after = await authorized(`${api}/api/node/info`);
    const afterBody = await after.json();
    expect(afterBody.challenge_generation).toBe(beforeGen + 1);
  });
});
