import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createReleaseCatalog } from '../src/central/releases';
import { createCentralServer } from '../src/central/server';
import { createNodeRegistry } from '../src/central/node-registry';
import type { NodeClient, NodeIdentityResponse } from '../src/central/node-client';
import { StorageIndexer } from '../src/storage/indexer';

const ADMIN = 'admin-release-token-0123456789012345';
const CENTRAL_KEY = 'r'.repeat(64);

const nodeIdentity: NodeIdentityResponse = {
  api_version: 'vaivar.node.v1',
  site_id: 'bootstrap-site',
  boot_id: 'boot-1',
  stream_id: 'stream-1',
  challenge_generation: 1,
  capabilities: ['events.read'],
  control_port: 3300,
  honeypot_port: 8081,
  service_profile: 'all',
};

const fakeClient = (): NodeClient => ({
  fetchIdentity: async () => nodeIdentity,
  fetchEvents: async () => ({ kind: 'unknown', message: 'not used' }) as never,
  fetchCommand: async () => ({ kind: 'unknown', message: 'not used' }) as never,
});

describe('central release and bootstrap distribution', () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'vaivar-release-'));
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  test('catalog ignores malformed, incomplete and path-escaping manifests', () => {
    const releaseDir = join(directory, 'releases');
    mkdirSync(releaseDir);
    const artifact = 'bundle.tar.gz';
    const contents = Buffer.from('release');
    writeFileSync(join(releaseDir, artifact), contents);
    const sha256 = createHash('sha256').update(contents).digest('hex');
    writeFileSync(join(releaseDir, 'release-1.0.0.manifest.json'), JSON.stringify({
      schema: 'vaivar.release.v1', version: '1.0.0', channel: 'stable', artifact,
      sha256, size_bytes: contents.length, created_at_ms: 10,
    }));
    writeFileSync(join(releaseDir, 'release-2.0.0.manifest.json'), JSON.stringify({
      schema: 'vaivar.release.v1', version: '2.0.0', channel: 'stable', artifact: '../secret',
      sha256, size_bytes: contents.length, created_at_ms: 20,
    }));
    expect(createReleaseCatalog(releaseDir).current()?.version).toBe('1.0.0');
  });

  test('bootstrap token downloads the current release and is consumed on registration', async () => {
    const releaseDir = join(directory, 'releases');
    mkdirSync(releaseDir);
    const artifact = 'vaivar-1.0.0.bundle.tar.gz';
    const contents = Buffer.from('offline-bundle');
    writeFileSync(join(releaseDir, artifact), contents);
    writeFileSync(join(releaseDir, 'release-1.0.0.manifest.json'), JSON.stringify({
      schema: 'vaivar.release.v1', version: '1.0.0', channel: 'stable', artifact,
      sha256: createHash('sha256').update(contents).digest('hex'),
      size_bytes: contents.length, created_at_ms: Date.now(),
    }));
    const installerPath = join(directory, 'honeypot-install.sh');
    writeFileSync(installerPath, '#!/usr/bin/env bash\nprintf installer\n');

    const storage = new StorageIndexer({ path: ':memory:' });
    await storage.init();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, fakeClient());
    const central = createCentralServer({
      port: 0,
      host: '127.0.0.1',
      storage,
      adminToken: ADMIN,
      operatorToken: 'operator-release-token-0123456789',
      nodeRegistry: registry,
      releaseDir,
      installerPath,
      allowPrivateHosts: true, // tests use RFC1918 hosts for honeypot simulation
    });
    await central.listen();
    const address = central.server.address() as { port: number };
    const base = `http://127.0.0.1:${address.port}`;

    try {
      // Humans authenticate via the session cookie (Keycloak or legacy token
      // login); the bootstrap-token endpoint requires manage_honeypots.
      const login = await fetch(base + '/api/v1/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: ADMIN }),
      });
      expect(login.status).toBe(200);
      const cookie = (login.headers.get('set-cookie') || '').split(';')[0];

      const issue = await fetch(base + '/api/v1/bootstrap/tokens', {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ttl_seconds: 900, metadata: { profile: 'all' } }),
      });
      expect(issue.status).toBe(201);
      const issued = await issue.json() as { bootstrap_token: string };
      expect(issued.bootstrap_token).toMatch(/^[A-Za-z0-9_-]{32,}$/);

      const bearerDenied = await fetch(base + '/api/v1/bootstrap/releases/current/download', {
        headers: { Authorization: `Bearer ${ADMIN}` },
      });
      expect(bearerDenied.status).toBe(401);

      const manifest = await fetch(base + '/api/v1/bootstrap/releases/current', {
        headers: { 'X-Vaivar-Bootstrap-Token': issued.bootstrap_token },
      });
      expect(manifest.status).toBe(200);
      expect((await manifest.json()).manifest.version).toBe('1.0.0');

      const download = await fetch(base + '/api/v1/bootstrap/releases/current/download', {
        headers: { 'X-Vaivar-Bootstrap-Token': issued.bootstrap_token },
      });
      expect(download.status).toBe(200);
      expect(download.headers.get('x-vaivar-release-version')).toBe('1.0.0');
      expect(Buffer.from(await download.arrayBuffer()).toString()).toBe('offline-bundle');

      const installer = await fetch(base + '/api/v1/bootstrap/installer', {
        headers: { 'X-Vaivar-Bootstrap-Token': issued.bootstrap_token },
      });
      expect(installer.status).toBe(200);
      expect(await installer.text()).toContain('printf installer');

      const registration = await fetch(base + '/api/v1/bootstrap/register', {
        method: 'POST',
        headers: { 'X-Vaivar-Bootstrap-Token': issued.bootstrap_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: '10.10.10.10', port: 3300, token: 'n'.repeat(32), tls: 'http', channel: 'legacy' }),
      });
      expect(registration.status).toBe(201);
      expect((await registration.json()).bootstrap_consumed).toBe(true);

      const replay = await fetch(base + '/api/v1/bootstrap/releases/current', {
        headers: { 'X-Vaivar-Bootstrap-Token': issued.bootstrap_token },
      });
      expect(replay.status).toBe(401);
    } finally {
      await central.close();
      await storage.close();
    }
  });
});
