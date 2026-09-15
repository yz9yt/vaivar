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

import type { IncomingMessage, ServerResponse } from 'http';
import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Bearer-token gate for the operator plane (dashboard + API + metrics).
 *
 * The honeypot surface (honeypot.ts) MUST remain tokenless: it is the
 * deception the attacker is meant to trip over. The control plane, in
 * contrast, is only reachable by the operator, so every non-health control
 * request must present the deployment-unique barrier token.
 */
export interface BarrierAuth {
  readonly enabled: boolean;
  /** Constant-time compare to avoid timing leaks on the token. */
  readonly verify: (token: string | null) => boolean;
  readonly verifyCookie: (token: string | null) => boolean;
  /** Set the HttpOnly cookie for the operator browser session. */
  readonly setCookie: (res: ServerResponse, role?: 'operator' | 'admin') => void;
}

/**
 * Create the auth guard. `token` is the deployment-unique barrier secret
 * (hex generated at deploy time). An invalid configuration denies access.
 */
export const createBarrierAuth = (token: string | undefined): BarrierAuth => {
  const normalized = (token ?? '').trim();
  const enabled = normalized.length >= 16;
  const sessionToken = createHmac('sha256', normalized).update('vaivar.operator.session.v1').digest('hex');

  const matches = (expected: string, candidate: string | null): boolean => {
    if (!enabled) return false;
    if (!candidate) return false;
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(candidate, 'utf8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  };

  return {
    enabled,
    verify: (candidate) => matches(normalized, candidate),
    verifyCookie: (candidate) => matches(sessionToken, candidate),
    setCookie: (res: ServerResponse, role: 'operator' | 'admin' = 'operator'): void => {
      if (!enabled) return;
      const name = role === 'admin' ? 'vaivar_admin' : 'vaivar_operator';
      res.setHeader(
        'Set-Cookie',
        `${name}=${sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`
      );
    },
  };
};

/** Extract the bearer token from an Authorization header, if any. */
export const bearerToken = (req: IncomingMessage): string | null => {
  const h = req.headers['authorization'];
  if (typeof h !== 'string' || h.length === 0) return null;
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
};

export interface SessionCookie {
  readonly name: 'vaivar_admin' | 'vaivar_operator';
  readonly value: string;
}

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

/** First of vaivar_admin, then vaivar_operator — admin is a superset of operator. */
export const sessionCookie = (req: IncomingMessage): SessionCookie | null => {
  const cookies = parseCookies(req);
  const admin = cookies.get('vaivar_admin');
  if (admin) return { name: 'vaivar_admin', value: admin };
  const operator = cookies.get('vaivar_operator');
  if (operator) return { name: 'vaivar_operator', value: operator };
  return null;
};

/** Extract the session cookie value (admin preferred, else operator). */
export const cookieToken = (req: IncomingMessage): string | null => {
  return sessionCookie(req)?.value ?? null;
};
