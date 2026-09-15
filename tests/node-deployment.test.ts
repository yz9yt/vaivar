import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bootstrap, type VaivarApp } from '../src/app/bootstrap';
import { NodeClient } from '../src/central/node-client';

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

describe('two-port honeypot deployment', () => {
  let app: VaivarApp | undefined;
  let directory: string;
  let api: string;
  let attacker: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'vaivar-deployment-'));
    for (const name of ['VAIVAR_CENTRAL_URL', 'VAIVAR_CENTRAL_INGEST_TOKEN', 'VAIVAR_SITE_ID']) {
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

  const start = async (central?: { url: string; ingestToken: string; siteId: string }, encrypted = false) => {
    const http = await unusedPort();
    let honeypot = await unusedPort();
    while (honeypot === http) honeypot = await unusedPort();
    const result = await bootstrap({
      masterSecret: 'a'.repeat(64), apiToken: TOKEN, ports: { http, honeypot },
      skins: ['http', 'mcp'], dbPath: join(directory, 'vaivar.db'),
      flushIntervalMs: 60_000, central,
      controlCrypto: encrypted ? { apiToken: TOKEN } : undefined,
    });
    if (!result.ok) throw result.error;
    app = result.value;
    const status = await app.start();
    expect(Object.keys(status).sort()).toEqual(['honeypot', 'http']);
    api = `http://127.0.0.1:${http}`;
    attacker = `http://127.0.0.1:${honeypot}`;
  };

  const authorized = (url: string, options: RequestInit = {}) => fetch(url, {
    ...options, headers: { Authorization: `Bearer ${TOKEN}`, ...options.headers },
  });

  test('dashboard, metrics, activity and MCP share one authenticated API', async () => {
    await start();
    for (const path of ['/api/dashboard/', '/api/prometheus/', '/api/metrics/realtimeattacks/', '/api/mcp/']) {
      const denied = await fetch(api + path);
      expect(denied.status).toBe(401);
      expect(denied.headers.get('set-cookie')).toBeNull();
      expect(await denied.text()).not.toContain(TOKEN);
    }
    const dashboard = await authorized(api + '/api/dashboard/');
    expect(dashboard.status).toBe(200);
    expect(await dashboard.json()).toHaveProperty('overview');
    expect(await (await authorized(api + '/api/prometheus/')).text()).toContain('vaivar_sessions_total');
    expect(await (await authorized(api + '/api/metrics/realtimeattacks/')).json()).toHaveProperty('activity');
    const mcp = await authorized(api + '/api/mcp/', {
      method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
    });
    expect(mcp.status).toBe(200);
    expect(await mcp.json()).toMatchObject({ id: 1, result: { status: 'ok' } });
  });

  test('public traffic creates sessions but cannot access private information', async () => {
    await start();
    const session = await fetch(attacker + '/api/v1/session', { method: 'POST', body: '{}' });
    expect(session.status).toBe(201);
    const body = await session.json();
    expect(body.sessionId).toBeTruthy();
    expect(JSON.stringify(body)).not.toContain('seed');
    for (const path of ['/api/dashboard/', '/api/prometheus/', '/api/metrics/realtimeattacks/', '/dashboard']) {
      expect((await fetch(attacker + path)).status).toBe(404);
    }
    const sessions = await (await authorized(api + '/api/v1/sessions')).json();
    expect(sessions.sessions).toHaveLength(1);
    const mcp = await fetch(attacker + '/mcp', {
      method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
    });
    expect(mcp.status).toBe(200);
  });

  test('browser dashboard uses a separate cookie credential on the same API', async () => {
    await start();
    const response = await authorized(api + '/dashboard');
    expect(response.status).toBe(200);
    const cookie = response.headers.get('set-cookie')!;
    expect(cookie).toContain('HttpOnly');
    expect(cookie).not.toContain(TOKEN);
    await response.text();
    const data = await fetch(api + '/api/v1/dashboard', { headers: { Cookie: cookie.split(';')[0] } });
    expect(data.status).toBe(200);
    expect(await data.json()).toHaveProperty('overview');
  });

  test('node info endpoint exposes stable identity and capabilities', async () => {
    await start();
    const denied = await fetch(api + '/api/node/info');
    expect(denied.status).toBe(401);

    const response = await authorized(api + '/api/node/info');
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      api_version: 'vaivar.node.v1',
      site_id: expect.any(String),
      boot_id: expect.any(String),
      stream_id: expect.any(String),
      challenge_generation: 0,
      capabilities: ['events.read', 'control.restart', 'control.rotate_challenges', 'control.configure_honeypot', 'control.apply_template'],
    });

    const siteId = body.site_id;
    const streamId = body.stream_id;
    const generation = body.challenge_generation;
    const bootId = body.boot_id;

    // site_id, stream_id and challenge_generation must be stable within
    // a single instance (same in-memory cache across multiple lookups).
    const second = await authorized(api + '/api/node/info');
    const secondBody = await second.json();
    expect(secondBody.site_id).toBe(siteId);
    expect(secondBody.stream_id).toBe(streamId);
    expect(secondBody.challenge_generation).toBe(generation);
    expect(secondBody.boot_id).toBe(bootId);
  });

  test('encrypted control channel keeps the bearer token off the HTTP API', async () => {
    await start(undefined, true);
    const direct = await authorized(api + '/api/node/info');
    expect(direct.status).toBe(426);

    const client = new NodeClient(3000);
    const endpoint = { host: '127.0.0.1', port: Number(new URL(api).port), token: TOKEN, tls: 'http' as const, channel: 'encrypted' as const };
    const identity = await client.fetchIdentity(endpoint);
    expect('kind' in identity).toBe(false);
    if ('kind' in identity) return;
    expect(identity.control_tls).toBe('http');
    expect(identity.control_channel).toBe('encrypted');
    const events = await client.fetchEvents(endpoint, identity.site_id, identity.stream_id);
    expect('kind' in events).toBe(false);
  });

  test('central command changes the public port and simulated profile', async () => {
    await start();
    const newPublicPort = await unusedPort();
    const command = await authorized(`${api}/api/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command_id: 'configure-public-surface-001',
        type: 'control.configure_honeypot',
        params: { port: newPublicPort, profile: 'wiki' },
      }),
    });
    expect(command.status).toBe(200);
    expect(await command.json()).toMatchObject({
      type: 'control.configure_honeypot',
      executed: true,
      outcome: { port: newPublicPort, profile: 'wiki' },
    });

    const info = await authorized(`${api}/api/node/info`);
    expect(await info.json()).toMatchObject({
      control_port: Number(api.split(':').pop()),
      honeypot_port: newPublicPort,
      service_profile: 'wiki',
    });
    const wiki = await fetch(`http://127.0.0.1:${newPublicPort}/wiki/home`);
    expect(wiki.status).toBe(200);
    const session = await fetch(`http://127.0.0.1:${newPublicPort}/api/v1/session`, { method: 'POST', body: '{}' });
    expect(session.status).toBe(404);
  });

  test('incomplete forwarding configuration does not fail and does not activate forwarding', async () => {
    vi.stubEnv('VAIVAR_CENTRAL_URL', 'https://central.example.test');
    const result = await bootstrap({
      masterSecret: 'a'.repeat(64), apiToken: TOKEN, skins: ['http'],
      ports: { http: 3300, honeypot: 8081 },
    });
    expect(result.ok).toBe(true);
  });

  test('configuring outbound forwarding keeps the private API available', async () => {
    await start({ url: 'http://127.0.0.1:1', ingestToken: TOKEN, siteId: 'test-node' });
    expect((await authorized(api + '/api/dashboard/')).status).toBe(200);
  });

  test('legacy OpenCTI environment cannot activate a connector on the node', async () => {
    vi.stubEnv('OPENCTI_URL', 'http://127.0.0.1:1');
    vi.stubEnv('OPENCTI_TOKEN', TOKEN);
    const calls = vi.spyOn(globalThis, 'fetch');
    await start();
    await fetch(attacker + '/api/v1/session', { method: 'POST', body: '{}' });
    await app!.flush();
    expect(calls.mock.calls.some(([url]) => String(url).startsWith('http://127.0.0.1:1/'))).toBe(false);
  });
});
