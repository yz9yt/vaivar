import { describe, it, expect } from 'vitest';
import { createHmac } from 'crypto';
import {
  ROLES,
  isRole,
  can,
  roleRank,
  roleAtLeast,
  encodeSessionCookie,
  decodeSessionCookie,
  SESSION_COOKIE,
  ROLE_PERMISSIONS,
  PERMISSIONS,
  type Role,
} from '../src/central/rbac';
import { mapGroupsToRole } from '../src/central/oidc';

// Pure RBAC unit tests (no I/O, no storage).
describe('rbac — four frozen roles', () => {
  test('ROLES and PERMISSIONS have expected members', () => {
    expect([...ROLES]).toEqual(['viewer', 'user', 'admin', 'superadmin']);
    expect(PERMISSIONS).toContain('read');
    expect(PERMISSIONS).toContain('manage_honeypots');
    expect(PERMISSIONS).toContain('manage_integrations');
    expect(PERMISSIONS).toContain('manage_system');
    expect(PERMISSIONS).not.toContain('manage_accounts');
  });

  test('isRole rejects unknown strings', () => {
    expect(isRole('viewer')).toBe(true);
    expect(isRole('user')).toBe(true);
    expect(isRole('admin')).toBe(true);
    expect(isRole('superadmin')).toBe(true);
    expect(isRole('operator')).toBe(false);
    expect(isRole('root')).toBe(false);
    expect(isRole('')).toBe(false);
  });

  describe('ROLE_PERMISSIONS (the matrix, server is law)', () => {
    const viewerPerms = ROLE_PERMISSIONS.viewer as readonly string[];
    const userPerms = ROLE_PERMISSIONS.user as readonly string[];
    const adminPerms = ROLE_PERMISSIONS.admin as readonly string[];
    const saPerms = ROLE_PERMISSIONS.superadmin as readonly string[];

    test('viewer can read only', () => {
      expect(viewerPerms).toEqual(['read']);
    });
    test('user = read + manage_honeypots', () => {
      expect(userPerms).toEqual(['read', 'manage_honeypots']);
    });
    test('admin adds manage_integrations', () => {
      expect(adminPerms).toEqual(['read', 'manage_honeypots', 'manage_integrations']);
    });
    test('superadmin adds manage_system (no "admin + one tick")', () => {
      expect(saPerms).toEqual([
        'read',
        'manage_honeypots',
        'manage_integrations',
        'manage_system',
      ]);
    });
    test('each tier strictly contains the previous', () => {
      for (const p of viewerPerms) expect(userPerms).toContain(p);
      for (const p of userPerms) expect(adminPerms).toContain(p);
      for (const p of adminPerms) expect(saPerms).toContain(p);
    });
  });

  test('can() grants correctly', () => {
    expect(can('viewer', 'read')).toBe(true);
    expect(can('viewer', 'manage_honeypots')).toBe(false);
    expect(can('user', 'manage_honeypots')).toBe(true);
    expect(can('user', 'manage_integrations')).toBe(false);
    expect(can('admin', 'manage_integrations')).toBe(true);
    expect(can('admin', 'manage_system')).toBe(false);
    expect(can('superadmin', 'manage_system')).toBe(true);
    expect(can('superadmin', 'read')).toBe(true);
  });

  test('roleRank orders tiers 1..4', () => {
    expect(roleRank('viewer' as Role)).toBe(1);
    expect(roleRank('user')).toBe(2);
    expect(roleRank('admin')).toBe(3);
    expect(roleRank('superadmin')).toBe(4);
  });

  test('roleAtLeast enforces the hierarchy (highest wins, eq allowed)', () => {
    expect(roleAtLeast('superadmin', 'admin')).toBe(true);
    expect(roleAtLeast('admin', 'superadmin')).toBe(false);
    expect(roleAtLeast('admin', 'admin')).toBe(true);
    expect(roleAtLeast('user', 'viewer')).toBe(true);
    expect(roleAtLeast('viewer', 'user')).toBe(false);
    expect(roleAtLeast('viewer', 'viewer')).toBe(true);
  });
});

describe('session cookie (single vaivar_session)', () => {
  const key = 'a'.repeat(32); // >=32 hex

  test('SESSION_COOKIE name is stable', () => {
    expect(SESSION_COOKIE).toBe('vaivar_session');
  });

  test('round-trips valid claims', () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      sub: 'kc-123', email: 'a@b.com', role: 'admin' as Role,
      iat: now, exp: now + 3600, auth: 'oidc' as const,
    };
    const value = encodeSessionCookie(key, claims);
    expect(value).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9]+$/);
    const decoded = decodeSessionCookie(key, value);
    expect(decoded).not.toBeNull();
    expect(decoded!.role).toBe('admin');
    expect(decoded!.email).toBe('a@b.com');
    expect(decoded!.sub).toBe('kc-123');
    expect(decoded!.auth).toBe('oidc');
  });

  test('rejects forged signature', () => {
    const now = Math.floor(Date.now() / 1000);
    const value = encodeSessionCookie(key, {
      sub: 'x', email: 'e', role: 'user',
      iat: now, exp: now + 3600, auth: 'bootstrap',
    });
    const [body, sig] = value.split('.');
    expect(decodeSessionCookie(key, `${body}.deadbeef`)).toBeNull();
  });

  test('rejects tampered role', () => {
    const now = Math.floor(Date.now() / 1000);
    const value = encodeSessionCookie(key, {
      sub: 'x', email: 'e', role: 'user',
      iat: now, exp: now + 3600, auth: 'bootstrap',
    });
    const [body] = value.split('.');
    const tampered = Buffer.from(JSON.stringify({ sub: 'x', email: 'e', role: 'superadmin', iat: now, exp: now + 3600, auth: 'bootstrap' }), 'utf8').toString('base64url');
    expect(decodeSessionCookie(key, `${tampered}.${'a'.repeat(64)}`)).toBeNull();
  });

  test('rejects expired claims', () => {
    const now = Math.floor(Date.now() / 1000);
    const value = encodeSessionCookie(key, {
      sub: 'x', email: 'e', role: 'user',
      iat: now - 7200, exp: now - 3600, auth: 'bootstrap',
    });
    expect(decodeSessionCookie(key, value)).toBeNull();
  });

  test('rejects unknown role in payload', () => {
    const now = Math.floor(Date.now() / 1000);
    const evil = Buffer.from(JSON.stringify({ sub: 'x', email: 'e', role: 'root', iat: now, exp: now + 3600, auth: 'oidc' }), 'utf8').toString('base64url');
    const sig = createHmac('sha256', key).update(`vaivar.session.v1:${evil}`).digest('hex');
    expect(decodeSessionCookie(key, `${evil}.${sig}`)).toBeNull();
  });
});

describe('Keycloak group → role mapping', () => {
  test('highest wins (superadmin beats viewer)', () => {
    expect(mapGroupsToRole(['vaivar-viewer', 'vaivar-superadmin'])).toBe('superadmin');
  });
  test('exact short names', () => {
    expect(mapGroupsToRole(['vaivar-user'])).toBe('user');
    expect(mapGroupsToRole(['vaivar-admin'])).toBe('admin');
    expect(mapGroupsToRole(['vaivar-viewer'])).toBe('viewer');
  });
  test('full paths accepted', () => {
    expect(mapGroupsToRole(['/vaivar-admin'])).toBe('admin');
  });
  test('no vaivar-* group → null (never silent viewer)', () => {
    expect(mapGroupsToRole(['some-other-group'])).toBeNull();
    expect(mapGroupsToRole([])).toBeNull();
    expect(mapGroupsToRole(undefined)).toBeNull();
  });
  test('unknown vaivar-* suffix is not a role', () => {
    expect(mapGroupsToRole(['vaivar-auditor'])).toBeNull();
  });
});
