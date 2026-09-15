import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { StorageIndexer } from '../src/storage/indexer';
import { createNodeRegistry, DuplicateNodeError } from '../src/central/node-registry';
import { createCentralServer } from '../src/central/server';
import type { NodeClient, NodeIdentityResponse } from '../src/central/node-client';
import { renderCentralDashboardHTML } from '../src/central/ui';
import { encodeSessionCookie } from '../src/central/rbac';

const OPERATOR = 'operator-token-16xx';
const ADMIN = 'admin-token-16xxxxx';
const CENTRAL_KEY = 'c'.repeat(64);

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

const identity = (siteId = 'site-alpha'): NodeIdentityResponse => ({
  api_version: 'vaivar.node.v1',
  site_id: siteId,
  boot_id: 'boot-1',
  stream_id: 'stream-1',
  challenge_generation: 1,
  capabilities: ['events.read'],
  control_port: 3300,
  honeypot_port: 8081,
  service_profile: 'wiki',
});

const fakeClient = (id: NodeIdentityResponse | { kind: string; message: string }): NodeClient =>
  ({
    fetchIdentity: async () => id as never,
    fetchEvents: async () => ({ kind: 'unknown', message: 'no' }) as never,
    fetchCommand: async () => ({ kind: 'unknown', message: 'no' }) as never,
  }) as unknown as NodeClient;

const cookieFrom = (res: Response): string => {
  const raw = res.headers.get('set-cookie') || '';
  return raw.split(';')[0];
};

describe('central UX redesign contracts', () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'vaivar-ux-'));
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  test('mapCentralNodeRow preserves SQL NULL last_contacted_at_ms', async () => {
    const storage = new StorageIndexer({ path: join(directory, 'n.db') });
    await storage.init();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, fakeClient(identity()));
    await registry.enroll({ host: '10.0.0.8', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' });
    const listed = await storage.listCentralNodes();
    expect(listed[0].last_contacted_at_ms).toBeNull();
    await storage.close();
  });

  test('duplicate enroll throws DuplicateNodeError and does not clobber', async () => {
    const storage = new StorageIndexer({ path: join(directory, 'd.db') });
    await storage.init();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, fakeClient(identity('site-dup')));
    await registry.enroll({ host: '10.0.0.9', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' });
    await expect(registry.enroll({ host: '10.0.0.9', port: 3301, token: 't'.repeat(16), tls: 'http', channel: 'legacy' })).rejects.toBeInstanceOf(DuplicateNodeError);
    const nodes = await registry.listNodes();
    expect(nodes).toHaveLength(1);
    expect(nodes[0].port).toBe(3300);
    await storage.close();
  });

  test('an existing node can be migrated from legacy HTTP auth to encrypted RPC', async () => {
    const storage = new StorageIndexer({ path: join(directory, 'migrate.db') });
    await storage.init();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, fakeClient({
      ...identity('site-migrate'),
      control_channel: 'encrypted',
      control_tls: 'http',
    }));
    await registry.enroll({ host: '10.0.0.10', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' });
    expect((await registry.getNode('site-migrate'))?.channel).toBe('legacy');
    await expect(registry.activateNode('site-migrate', 't'.repeat(16), 'encrypted')).resolves.toBe(true);
    expect((await registry.getNode('site-migrate'))?.channel).toBe('encrypted');
    await storage.close();
  });

  test('listCentralEvents returns latest first', async () => {
    const storage = new StorageIndexer({ path: join(directory, 'e.db') });
    await storage.init();
    await storage.saveCentralEvent('s1', 'st', 'e1', '1', 1000, 'old', { session_id: 'sess-old' });
    await storage.saveCentralEvent('s1', 'st', 'e2', '2', 2000, 'new', { session_id: 'sess-new' });
    const rows = await storage.listCentralEvents(null, 10);
    expect(rows[0].event_type).toBe('new');
    expect(rows[1].event_type).toBe('old');
    await storage.close();
  });

  test('operator (user role) can preview/enroll; viewer cannot; admin can; GET nodes returns JSON null', async () => {
    const storage = new StorageIndexer({ path: join(directory, 'http.db') });
    await storage.init();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, fakeClient(identity('site-http')));
    const port = await unusedPort();
    const central = createCentralServer({
      port,
      host: '127.0.0.1',
      storage,
      operatorToken: OPERATOR,
      adminToken: ADMIN,
      nodeRegistry: registry,
      devMode: false,
      allowPrivateHosts: true, // tests enroll RFC1918 honeypot fixtures
    });
    await central.listen();
    const base = `http://127.0.0.1:${port}`;
    // Test server sets no sessionKey/centralKey, so it falls back to the
    // default session key — used here to forge a read-only viewer cookie.
    const SESSION_KEY = 'vaivar-session-local';
    const viewerCookie = (() => {
      const now = Math.floor(Date.now() / 1000);
      return `vaivar_session=${encodeSessionCookie(SESSION_KEY, {
        sub: 'viewer-1', email: 'viewer@local', role: 'viewer',
        iat: now, exp: now + 3600, auth: 'oidc',
      })}`;
    })();
    try {
      const opLogin = await fetch(base + '/api/v1/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: OPERATOR }),
      });
      expect(opLogin.status).toBe(200);
      const opCookie = cookieFrom(opLogin);
      expect(opCookie.startsWith('vaivar_session=')).toBe(true);

      // operator token → user role (fleet hand): may manage honeypots.
      const opPreview = await fetch(base + '/api/v1/nodes/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: opCookie },
        body: JSON.stringify({ host: '10.1.1.1', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' }),
      });
      expect(opPreview.status).toBe(200);

      // A viewer (read-only) cannot manage honeypots → rejected.
      const denied = await fetch(base + '/api/v1/nodes/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: viewerCookie },
        body: JSON.stringify({ host: '10.1.1.1', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' }),
      });
      expect(denied.status).toBe(401);

      const adminLogin = await fetch(base + '/api/v1/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: ADMIN }),
      });
      expect(adminLogin.status).toBe(200);
      const adminCookie = cookieFrom(adminLogin);
      expect(adminCookie.startsWith('vaivar_session=')).toBe(true);

      const me = await fetch(base + '/api/v1/me', { headers: { Cookie: adminCookie } });
      expect(me.status).toBe(200);
      expect(await me.json()).toMatchObject({ role: 'admin', dev_mode: false });

      const ipv6 = await fetch(base + '/api/v1/nodes/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
        body: JSON.stringify({ host: '2001:db8::1', port: 3300, token: 't'.repeat(16), tls: 'http' }),
      });
      expect(ipv6.status).toBe(400);

      const preview = await fetch(base + '/api/v1/nodes/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
        body: JSON.stringify({ host: '10.1.1.1', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' }),
      });
      expect(preview.status).toBe(200);
      const previewBody = await preview.json();
      expect(previewBody.ok).toBe(true);
      expect(previewBody.duplicate).toBe(false);
      expect(previewBody.site_id).toBe('site-http');

      const enroll = await fetch(base + '/api/v1/nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
        body: JSON.stringify({ host: '10.1.1.1', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' }),
      });
      expect(enroll.status).toBe(201);

      const list = await fetch(base + '/api/v1/nodes', { headers: { Cookie: adminCookie } });
      const listed = await list.json();
      expect(listed.nodes[0].last_contacted_at_ms).toBeNull();
      expect(listed.nodes[0]).toMatchObject({ honeypot_port: 8081, service_profile: 'wiki' });

      await storage.saveCentralEvent('site-http', 'st', 'old', '1', 1, 'old.type', { session_id: 'a' });
      await storage.saveCentralEvent('site-http', 'st', 'new', '2', 9, 'new.type', { session_id: 'b' });
      const events = await fetch(base + '/api/v1/events?limit=10', { headers: { Cookie: adminCookie } });
      const evBody = await events.json();
      expect(evBody.events[0].type).toBe('new.type');
      expect(evBody.events[0].session_id).toBe('b');
      expect(evBody.has_more).toBe(false);

      const again = await fetch(base + '/api/v1/nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
        body: JSON.stringify({ host: '10.1.1.1', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' }),
      });
      expect(again.status).toBe(409);
    } finally {
      await central.close();
      await storage.close();
    }
  });

  test('dashboard HTML keeps four-item nav and add-honeypot empty state', () => {
    const html = renderCentralDashboardHTML('1.0.0');
    expect(html).toContain('data-tab="overview"');
    expect(html).toContain('data-tab="honeypots"');
    expect(html).toContain('data-tab="activity"');
    expect(html).toContain('data-tab="settings"');
    expect(html).not.toContain('data-tab="sessions"');
    expect(html).toContain('id="mode-sessions"');
    expect(html).toContain('scripts/deploy.sh');
    expect(html).toContain('Add honeypot');
    expect(html).toContain('id="main"');
    expect(html).toContain('NODE_STALE_MS = 90_000');
    expect(html).toContain('Exposed honeypot port');
    expect(html).toContain('configure_honeypot');
    expect(html).toContain('btn-prepare-bootstrap');
    expect(html).toContain('/api/v1/bootstrap/installer');
    expect(html).toContain('enroll-project-name');
    expect(html).toContain('enroll-site-id');
    expect(html).toContain('enroll-channel');
    expect(html).toContain('--project-name');
    expect(html).toContain('--site-id');
    expect(html).toContain('--control-channel encrypted');
    expect(html).not.toContain('SECURE');
    expect(html).not.toContain('Threat Feed');
    expect(html).toContain('Honeypot Customization');
    expect(html).toContain('data-event-filter="attacks"');
    expect(html).toContain('btn-save-node-meta');
  });

  test('node metadata (name, notes) can be updated and persists in storage', async () => {
    const storage = new StorageIndexer({ path: join(directory, 'meta.db') });
    await storage.init();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, fakeClient(identity('site-meta')));
    const port = await unusedPort();
    const central = createCentralServer({
      port,
      host: '127.0.0.1',
      storage,
      operatorToken: OPERATOR,
      adminToken: ADMIN,
      nodeRegistry: registry,
      devMode: false,
      allowPrivateHosts: true, // tests enroll RFC1918 honeypot fixtures
    });
    await central.listen();
    const base = `http://127.0.0.1:${port}`;
    try {
      const adminLogin = await fetch(base + '/api/v1/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: ADMIN }),
      });
      const adminCookie = cookieFrom(adminLogin);

      await fetch(base + '/api/v1/nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
        body: JSON.stringify({ host: '10.2.2.2', port: 3300, token: 't'.repeat(16), tls: 'http', channel: 'legacy' }),
      });

      const updateMeta = await fetch(base + '/api/v1/nodes/site-meta/metadata', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
        body: JSON.stringify({ name: 'Frankfurt Production Edge', notes: 'Simulates internal Confluence. Alert SOC.' }),
      });
      expect(updateMeta.status).toBe(200);
      const metaRes = await updateMeta.json();
      expect(metaRes.name).toBe('Frankfurt Production Edge');
      expect(metaRes.notes).toBe('Simulates internal Confluence. Alert SOC.');

      // Verify persisted in storage
      const node = await storage.getCentralNode('site-meta');
      expect(node?.name).toBe('Frankfurt Production Edge');
      expect(node?.notes).toBe('Simulates internal Confluence. Alert SOC.');

      // Save an attack event and test rich description
      await storage.saveCentralEvent('site-meta', 'stream-1', 'flag-evt-1', '1', Date.now(), 'flag.hit', {
        session_id: 'sess-attack-1',
        type: 'flag.hit',
        flag: { code: 'FLAG_WIN', level: 3, id: 'win' },
        context: { skin: 'openapi', node_id: '/api/v1/auth/keys', hint: 'Admin token leaked' },
      });

      const evRes = await fetch(base + '/api/v1/events?limit=10', { headers: { Cookie: adminCookie } });
      const evJson = await evRes.json();
      expect(evJson.events[0].severity).toBe('critical');
      expect(evJson.events[0].summary).toContain('Compromise Trap Triggered: [FLAG_WIN · Level 3]');
      expect(evJson.events[0].summary).toContain('Admin token leaked');
      expect(evJson.events[0].trap_path).toBe('/api/v1/auth/keys');
    } finally {
      await central.close();
      await storage.close();
    }
  });
});
