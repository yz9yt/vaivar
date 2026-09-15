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

// Role-Based Access Control for the Central control plane.
// Design contract: Central authentication policy.
//
// Humans carry one of four roles. Permissions are a pure matrix keyed by role
// (no per-user ACLs, no "permission painter" UI). The role is granted by
// Keycloak group membership (highest wins) and reflected in a single signed
// Central session cookie. Machines keep barrier/ingest tokens — never a role.

import { createHmac, timingSafeEqual } from 'crypto';

// ── Roles (tier hierarchy) ─────────────────────────────────────────────────
// Frozen set. viewer < user < admin < superadmin.
export type Role = 'viewer' | 'user' | 'admin' | 'superadmin';

export const ROLES: readonly Role[] = ['viewer', 'user', 'admin', 'superadmin'];

const RANK: Record<Role, 1 | 2 | 3 | 4> = {
  viewer: 1,
  user: 2,
  admin: 3,
  superadmin: 4,
};

// ── Permissions ────────────────────────────────────────────────────────────
// Capability the server actually gates on. Grouped, not per-resource.
export const PERMISSIONS = [
  'read', // dashboard, events, nodes, stats, activity, metrics (panel)
  'manage_honeypots', // enroll, command, configure, restart, rotate, PATCH token
  'manage_integrations', // settings GET/POST, integrations, Splunk export
  'manage_system', // releases, installer, central key rotation, data purge, break-glass
] as const;
export type Permission = (typeof PERMISSIONS)[number];

// Pure map: role → its permission set. UI only mirrors this; the server is law.
export const ROLE_PERMISSIONS: Record<Role, ReadonlyArray<Permission>> = {
  viewer: ['read'],
  user: ['read', 'manage_honeypots'],
  admin: ['read', 'manage_honeypots', 'manage_integrations'],
  superadmin: ['read', 'manage_honeypots', 'manage_integrations', 'manage_system'],
};

// ── Pure helpers ───────────────────────────────────────────────────────────
export const isRole = (v: unknown): v is Role =>
  typeof v === 'string' && (ROLES as readonly string[]).includes(v);

export const can = (role: Role, perm: Permission): boolean =>
  (ROLE_PERMISSIONS[role] as readonly string[]).includes(perm);

export const roleRank = (role: Role): number => RANK[role];

/** True iff `role` ranks at least as high as `target` (hierarchy check). */
export const roleAtLeast = (role: Role, target: Role): boolean => RANK[role] >= RANK[target];

// ── Session cookie (single, signed) ───────────────────────────────────────
// One cookie: `vaivar_session`. Value = `${base64url(payload)}.${hmacHex}`.
// Payload = { sub, email, role, iat, exp, auth }. No Keycloak JWT rides on the
// Central API — only this Central-issued session does. HMAC under
// `VAIVAR_SESSION_KEY` (≥32 hex). Timing-safe compare on the signature.

export const SESSION_COOKIE = 'vaivar_session';

export type SessionAuth = 'oidc' | 'bootstrap' | 'dev';

export interface SessionClaims {
  sub: string; // Keycloak `sub` (or 'dev' / 'bootstrap')
  email: string;
  role: Role;
  iat: number;
  exp: number;
  auth: SessionAuth;
}

const base64url = (buf: Buffer): string => buf.toString('base64url');

export const encodeSessionCookie = (
  sessionKey: string,
  claims: SessionClaims,
): string => {
  const body = base64url(Buffer.from(JSON.stringify(claims), 'utf8'));
  const sig = createHmac('sha256', sessionKey).update(`vaivar.session.v1:${body}`).digest('hex');
  return `${body}.${sig}`;
};

export const decodeSessionCookie = (sessionKey: string, raw: string | undefined | null): SessionClaims | null => {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  const dot = raw.lastIndexOf('.');
  if (dot <= 0) return null;
  const body = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = createHmac('sha256', sessionKey).update(`vaivar.session.v1:${body}`).digest('hex');
  let a: Buffer, b: Buffer;
  try {
    a = Buffer.from(sig, 'hex');
    b = Buffer.from(expected, 'hex');
  } catch {
    return null;
  }
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as SessionClaims;
    if (!isRole(claims.role)) return null;
    if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) return null;
    return claims;
  } catch {
    return null;
  }
};
