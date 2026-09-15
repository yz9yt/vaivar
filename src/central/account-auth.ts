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

// Session authentication for the Central control plane.
// Design contract: Central authentication policy.
//
// Humans carry exactly ONE signed session cookie (`vaivar_session`) whose
// claims { sub, email, role, iat, exp, auth } are issued after an OIDC login
// (or the bootstrap/dev fallback). The role inside the claims is what gates
// every permission via the pure RBAC matrix. Machines keep static bearer
// tokens (ingest/metrics) and are resolved elsewhere — never through roles.

import type { IncomingMessage, ServerResponse } from 'http';
import {
  can,
  decodeSessionCookie,
  encodeSessionCookie,
  isRole,
  roleAtLeast,
  SESSION_COOKIE,
  type Permission,
  type Role,
  type SessionClaims,
} from './rbac';

export interface SessionContext {
  /** HMAC key for the session cookie (VAIVAR_SESSION_KEY, ≥32 hex). */
  readonly sessionKey: string;
  /** When true the console is open without auth (local lab only). */
  readonly devMode?: boolean;
}

/** Legacy role-tiered cookies dropped during the Keycloak migration. */
const LEGACY_COOKIE_NAMES = [
  'vaivar_operator',
  'vaivar_admin',
  'vaivar_superadmin',
  'vaivar_user',
] as const;

const parseCookies = (req: IncomingMessage): Map<string, string> => {
  const raw = req.headers['cookie'];
  const out = new Map<string, string>();
  if (typeof raw !== 'string' || raw.length === 0) return out;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out.set(k, v.join('='));
  }
  return out;
};

/** Extract the bearer token from an Authorization header, if any. */
export const bearerToken = (req: IncomingMessage): string | null => {
  const h = req.headers['authorization'];
  if (typeof h !== 'string' || h.length === 0) return null;
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
};

/**
 * Resolve the human caller from the session cookie. Returns null when the
 * cookie is missing, forged, expired, or the role is not one of the four
 * frozen roles. In devMode the caller is always a dev superadmin.
 */
export const resolveCaller = (req: IncomingMessage, ctx: SessionContext): SessionClaims | null => {
  if (ctx.devMode) {
    const now = Math.floor(Date.now() / 1000);
    return { sub: 'dev', email: 'dev@localhost', role: 'superadmin', iat: now, exp: now + 3600, auth: 'dev' };
  }
  const cookies = parseCookies(req);
  return decodeSessionCookie(ctx.sessionKey, cookies.get(SESSION_COOKIE));
};

/** Issue the HttpOnly session cookie (12h lifetime). */
export const issueSessionCookie = (res: ServerResponse, sessionKey: string, claims: SessionClaims): void => {
  const value = encodeSessionCookie(sessionKey, claims);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);
};

/** Clear the session cookie plus any legacy role-tiered cookies. */
export const clearSessionCookie = (res: ServerResponse): void => {
  const parts = [SESSION_COOKIE, ...LEGACY_COOKIE_NAMES].map(
    (name) => `${name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
  );
  res.setHeader('Set-Cookie', parts.join(', '));
};

/**
 * Permission gate: resolve the caller's session, then check its role grants
 * the permission. Pure RBAC decision; sync because the session is stateless.
 */
export const permit = (req: IncomingMessage, ctx: SessionContext, permission: Permission): boolean => {
  const caller = resolveCaller(req, ctx);
  return caller !== null && can(caller.role, permission);
};

/** Rank gate: caller must hold at least `min` role. */
export const callerAtLeast = (req: IncomingMessage, ctx: SessionContext, min: Role): boolean => {
  const caller = resolveCaller(req, ctx);
  return caller !== null && roleAtLeast(caller.role, min);
};

/** Validate a raw role string coming from config/tests. */
export const ensureRole = (v: unknown): Role | null => (isRole(v) ? v : null);
