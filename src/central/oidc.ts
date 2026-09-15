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

// OIDC Authorization Code + PKCE for the Central control plane.
// Design contract: Central authentication policy.
//
// Humans authenticate against Keycloak (realm `vaivar`). Central exchanges the
// authorization code server-side (confidential client), verifies the id_token
// (iss/aud/exp/nonce via JWKS), maps `vaivar-*` group membership to one of the
// four frozen roles (highest wins; no group → no session), and issues its own
// signed session cookie. The Keycloak JWT never rides on Central API calls.
//
// Machines never use OIDC: ingest/metrics keep static bearer tokens.

import { createHash, randomBytes } from 'crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { ROLES, type Role } from './rbac';

export interface OidcConfig {
  readonly issuer: string; // e.g. https://keycloak.example.com/realms/vaivar
  readonly clientId: string; // vaivar-central
  readonly clientSecret: string;
  readonly redirectUri: string; // e.g. https://central.example.com/api/v1/oidc/callback
}

export interface OidcEndpoints {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly userinfo_endpoint: string;
  readonly jwks_uri: string;
  readonly end_session_endpoint?: string;
}

export interface CallerIdentity {
  readonly sub: string;
  readonly email: string;
  readonly role: Role;
}

// ── Config from environment ────────────────────────────────────────────────

export const readOidcConfig = (env: NodeJS.ProcessEnv = process.env): OidcConfig | null => {
  const issuer = env.VAIVAR_OIDC_ISSUER?.trim();
  const clientId = env.VAIVAR_OIDC_CLIENT_ID?.trim();
  const clientSecret = env.VAIVAR_OIDC_CLIENT_SECRET?.trim();
  const redirectUri = env.VAIVAR_OIDC_REDIRECT_URI?.trim();
  if (!issuer || !clientId || !clientSecret || !redirectUri) return null;
  return { issuer, clientId, clientSecret, redirectUri };
};

export const isOidcConfigured = (env: NodeJS.ProcessEnv = process.env): boolean =>
  readOidcConfig(env) !== null;

// ── Discovery (cached, TTL 1h) ─────────────────────────────────────────────

let discoveryCache: { issuer: string; endpoints: OidcEndpoints; fetchedAt: number } | null = null;
const DISCOVERY_TTL_MS = 3_600_000;

export const fetchOidcEndpoints = async (issuer: string, fetchImpl: typeof fetch = fetch): Promise<OidcEndpoints> => {
  const cached = discoveryCache;
  if (cached && cached.issuer === issuer && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) {
    return cached.endpoints;
  }
  const res = await fetchImpl(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
  const raw = (await res.json()) as Record<string, unknown>;
  const str = (k: string): string => {
    const v = raw[k];
    if (typeof v !== 'string' || v.length === 0) throw new Error(`OIDC discovery missing ${k}`);
    return v;
  };
  const endpoints: OidcEndpoints = {
    issuer: str('issuer'),
    authorization_endpoint: str('authorization_endpoint'),
    token_endpoint: str('token_endpoint'),
    userinfo_endpoint: str('userinfo_endpoint'),
    jwks_uri: str('jwks_uri'),
    end_session_endpoint: typeof raw.end_session_endpoint === 'string' ? raw.end_session_endpoint : undefined,
  };
  discoveryCache = { issuer, endpoints, fetchedAt: Date.now() };
  return endpoints;
};

/** Test hook: drop the cached discovery document. */
export const resetOidcDiscoveryCache = (): void => {
  discoveryCache = null;
};

// ── PKCE store (in-memory, one-shot, TTL 10 min) ───────────────────────────

interface PkceEntry {
  readonly verifier: string;
  readonly nonce: string;
  readonly createdAt: number;
}

const pkceStore = new Map<string, PkceEntry>();
const PKCE_TTL_MS = 600_000;

// Periodic sweep so abandoned states do not accumulate.
let sweeperStarted = false;
const startSweeper = (): void => {
  if (sweeperStarted) return;
  sweeperStarted = true;
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [state, entry] of pkceStore) {
      if (now - entry.createdAt > PKCE_TTL_MS) pkceStore.delete(state);
    }
  }, 300_000);
  timer.unref?.();
};

const codeChallenge = (verifier: string): string =>
  createHash('sha256').update(verifier).digest('base64url');

// ── Group → role mapping ───────────────────────────────────────────────────
// One Keycloak group = one role. Highest rank wins. No `vaivar-*` group →
// null (caller gets 403, never a silent viewer downgrade).

const GROUP_PREFIX = 'vaivar-';

export const mapGroupsToRole = (groups: unknown): Role | null => {
  if (!Array.isArray(groups)) return null;
  const names = groups.filter((g): g is string => typeof g === 'string').map((g) =>
    // Accept both short names and full paths ("/vaivar-admin").
    g.startsWith('/') ? g.slice(1) : g,
  );
  // Highest rank first.
  for (const role of [...ROLES].reverse()) {
    if (names.includes(`${GROUP_PREFIX}${role}`)) return role;
  }
  return null;
};

// ── Authorize URL (start of the flow) ──────────────────────────────────────

export const buildAuthorizeUrl = async (
  cfg: OidcConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<{ url: string; state: string }> => {
  const endpoints = await fetchOidcEndpoints(cfg.issuer, fetchImpl);
  const state = randomBytes(16).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const verifier = randomBytes(48).toString('base64url'); // 64 chars, within 43-128
  pkceStore.set(state, { verifier, nonce, createdAt: Date.now() });
  startSweeper();
  const url = new URL(endpoints.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', codeChallenge(verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  return { url: url.toString(), state };
};

// ── Code exchange + id_token verification (callback) ───────────────────────

export interface ExchangeResult {
  readonly identity: CallerIdentity;
  readonly idToken: string;
}

export const exchangeCode = async (
  cfg: OidcConfig,
  query: URLSearchParams,
  fetchImpl: typeof fetch = fetch,
): Promise<ExchangeResult | null> => {
  const state = query.get('state');
  const code = query.get('code');
  if (!state || !code) return null;

  // One-shot state: replay or unknown state is rejected.
  const entry = pkceStore.get(state);
  pkceStore.delete(state);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > PKCE_TTL_MS) return null;

  const endpoints = await fetchOidcEndpoints(cfg.issuer, fetchImpl);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    code_verifier: entry.verifier,
  });
  const tokenRes = await fetchImpl(endpoints.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!tokenRes.ok) return null;
  const tokens = (await tokenRes.json()) as { id_token?: string; access_token?: string };
  const idToken = tokens.id_token;
  const accessToken = tokens.access_token;
  if (typeof idToken !== 'string' || idToken.length === 0) return null;
  if (typeof accessToken !== 'string' || accessToken.length === 0) return null;

  // Verify id_token: signature (JWKS), iss, aud, exp, and the PKCE nonce.
  const JWKS = createRemoteJWKSet(new URL(endpoints.jwks_uri));
  let sub: string;
  try {
    const { payload } = await jwtVerify(idToken, JWKS, {
      issuer: endpoints.issuer,
      audience: cfg.clientId,
    });
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) return null;
    // Manual nonce check (jose does not enforce it via options).
    if (typeof payload.nonce !== 'string' || payload.nonce !== entry.nonce) return null;
    sub = payload.sub;
  } catch {
    return null;
  }

  // UserInfo for email + groups (groups claim mapped on Keycloak side).
  const uiRes = await fetchImpl(endpoints.userinfo_endpoint, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!uiRes.ok) return null;
  const userinfo = (await uiRes.json()) as Record<string, unknown>;
  const role = mapGroupsToRole(userinfo.groups);
  if (!role) return null; // no group = no session (plan: "No group = 403")
  const email =
    typeof userinfo.email === 'string' && userinfo.email.length > 0
      ? userinfo.email
      : typeof userinfo.preferred_username === 'string'
        ? userinfo.preferred_username
        : sub;

  return { identity: { sub, email, role }, idToken };
};

// ── Logout ─────────────────────────────────────────────────────────────────

export const buildEndSessionUrl = async (
  cfg: OidcConfig,
  postLogoutRedirectUri: string,
  idToken?: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string | null> => {
  const endpoints = await fetchOidcEndpoints(cfg.issuer, fetchImpl);
  if (!endpoints.end_session_endpoint) return null;
  const url = new URL(endpoints.end_session_endpoint);
  url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);
  if (idToken) url.searchParams.set('id_token_hint', idToken);
  return url.toString();
};
