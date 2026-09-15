/**
 * Tests for centralized versioning and dashboard footer presentation.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { VAIVAR_VERSION, VAIVAR_NAME, VAIVAR_CODENAME, VAIVAR_SPEC_VERSION } from '../src/version';
import { renderCentralDashboardHTML } from '../src/central/ui';
import { createCentralServer } from '../src/central/server';
import { createStorage } from '../src/storage/indexer';
import http from 'http';

describe('Centralized Application Version', () => {
  it('matches package.json version', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
    expect(VAIVAR_VERSION).toBe(pkg.version);
    expect(VAIVAR_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('exports platform metadata constants', () => {
    expect(VAIVAR_NAME).toContain('vAIvar');
    expect(VAIVAR_CODENAME).toBe('Autonomous Deception Matrix');
    expect(VAIVAR_SPEC_VERSION).toBe('vaivar.event.v2');
  });

  it('renders centralized version in the HTML dashboard footer and settings', () => {
    const html = renderCentralDashboardHTML(VAIVAR_VERSION);

    // Minimalist Flat footer present with version
    expect(html).toContain('class="app-footer"');
    expect(html).toContain(`v${VAIVAR_VERSION}`);
    expect(html).toContain(VAIVAR_CODENAME);
    expect(html).toContain('vAIvar Central');
    expect(html).not.toContain('vAIvar Central SOC');

    // Users & permissions panel is informational: human identities live in
    // Keycloak (no client-side account CRUD).
    expect(html).toContain('Users & permissions');
    expect(html).toContain('Keycloak');
    expect(html).toContain('vaivar-viewer');
    expect(html).toContain('vaivar-superadmin');
    expect(html).not.toContain('Create account');

    // Sidebar is clean without duplicate version badges
    expect(html).not.toContain('brand-version-badge');
  });

  it('exposes version in central server /health probe', async () => {
    const storage = createStorage(':memory:');
    const serverInstance = createCentralServer({
      port: 0,
      host: '127.0.0.1',
      storage,
      operatorToken: 'dev',
    });

    await serverInstance.listen();
    const addr = serverInstance.server.address() as { port: number };

    try {
      const res = await new Promise<{ status: number; data: Record<string, unknown> }>((resolve, reject) => {
        http.get(`http://127.0.0.1:${addr.port}/health`, (r) => {
          let body = '';
          r.on('data', (chunk) => { body += chunk; });
          r.on('end', () => {
            try {
              resolve({ status: r.statusCode || 0, data: JSON.parse(body) });
            } catch (err) {
              reject(err);
            }
          });
        }).on('error', reject);
      });

      expect(res.status).toBe(200);
      expect(res.data.status).toBe('ok');
      expect(res.data.version).toBe(VAIVAR_VERSION);
    } finally {
      await serverInstance.close();
      storage.close();
    }
  });
});
