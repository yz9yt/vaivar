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

import fs from 'fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import type { StorageIndexer } from '../storage/indexer';
import { createBarrierAuth, bearerToken } from '../server/auth';
import {
  resolveCaller,
  issueSessionCookie,
  clearSessionCookie,
  type SessionContext,
} from './account-auth';
import {
  can,
  ROLE_PERMISSIONS,
  type Role,
  type SessionAuth,
} from './rbac';
import {
  readOidcConfig,
  buildAuthorizeUrl,
  exchangeCode,
  buildEndSessionUrl,
  type CallerIdentity,
} from './oidc';
import type { Event } from '../types/events';
import type { NodeClient } from './node-client';
import type { NodeRegistry, NodeRegistrationRequest } from './node-registry';
import { DuplicateNodeError } from './node-registry';
import type { Poller } from './poller';
import { persistEvent } from './ingest';
import type { SplunkHecAdapter } from './splunk-hec';
import type { OpenCTIConnector } from '../cti/connector';
import type { IntegrationKind } from '../storage/types';
import { renderCentralDashboardHTML } from './ui';
import { VAIVAR_VERSION } from '../version';
import { isHoneypotProfile } from '../node/config';
import { validateHoneypotTemplate } from '../templates/types';
import { createReleaseCatalog, type ReleaseCatalog } from './releases';
import { readVaivarLogoSvg, VAIVAR_LOGO_URL } from '../branding';
import {
  controlEnvelopeReplayKey,
  deriveControlKey,
  openControlMessage,
  sealControlMessage,
  type ControlResponse,
} from '../security/control-channel';
import { validateOutboundUrl, isPublicHost } from '../security/url-validation';
import {
  ConsoleDefense,
  CENTRAL_SITE_ID,
  CONSOLE_ATTACKER_CONFIDENCE,
  CONSOLE_DEFENSE_DRAIN_INTERVAL_MS,
  consoleAttackerId,
  consoleAttackerLevel,
  consoleAttackerSeverity,
} from './console-defense';

/**
 * Central control plane. Multiple Edge honeypots forward their events here
 * inside application-encrypted envelopes, and the operator reads a single
 * consolidated view without reaching into any site.
 *
 * The central plane is the ONLY place the operator needs network access to;
 * Edge nodes expose no dashboard and Central talks to their control port over
 * HTTP carrying application-encrypted RPC envelopes.
 */
export interface CentralServerConfig {
  readonly port: number;
  readonly host: string;
  readonly storage: StorageIndexer;
  /** Token Edges present when pushing events. Distinct from the operator token. */
  readonly ingestToken?: string;
  /** Token the operator dashboard/UI presents. Set to "dev" to disable auth. */
  readonly operatorToken?: string;
  /** Token for admin-level operator actions (node enrollment). */
  readonly adminToken?: string;
  /** Superadmin token (total control, incl. manage_system). Optional. */
  readonly superadminToken?: string;
  /** Break-glass token (>=16 chars) that logs in as superadmin when Keycloak
   *  is unavailable. Optional; only used as a login fallback. */
  readonly bootstrapToken?: string;
  /** Key used to sign the Central session cookie (>=32 hex). */
  readonly sessionKey?: string;
  /** Node registry for enrollment lifecycle. */
  readonly nodeRegistry?: NodeRegistry;
  /** Central polling collector. */
  readonly poller?: Poller;
  /** Splunk HEC adapter, if configured. */
  readonly splunkHec?: SplunkHecAdapter;
  /** OpenCTI connectors by configuration name, if any are enabled. */
  readonly openCTIConnectors?: Map<string, OpenCTIConnector>;
  /** Central key for decrypting node secrets. */
  readonly centralKey?: string;
  /** Client for talking to registered node APIs (identity, events, commands). */
  readonly nodeClient?: NodeClient;
  /** Directory containing immutable release bundles and manifests. */
  readonly releaseDir?: string;
  /** Host-side installer served to an authorized bootstrap client. */
  readonly installerPath?: string;
  /** When true (or operatorToken === "dev"), the operator dashboard and its
   *  API are served without authentication. Use ONLY for local dev / testing. */
  readonly devMode?: boolean;
  /** Authentication mode for UI/API access.
   *   "none"  → open access, no authentication required (default).
   *   "legacy" → token login required (operator/admin/superadmin).
   *   "oidc"   → Keycloak SSO required (fallback to bootstrap token if configured).
   */
  readonly authMode?: 'none' | 'legacy' | 'oidc';
  /**
   * When true, the SSRF guard allows private (RFC1918 / loopback / link-local)
   * hosts in node enrollment and integration URLs. Use when Central and Edge
   * share a private network (e.g. Docker bridge). Default: false.
   */
  readonly allowPrivateHosts?: boolean;
  /** Optional console self-defense configuration (rate limits, ban thresholds). */
  readonly defense?: Partial<import('./console-defense').ConsoleDefenseConfig>;
  /** Trust x-forwarded-for for client-IP derivation (only behind a trusted
   *  reverse proxy). Default false: spoofed headers would poison the defense. */
  readonly trustProxy?: boolean;
}

export interface CentralServer {
  readonly server: ReturnType<typeof createServer>;
  readonly listen: () => Promise<void>;
  readonly close: () => Promise<void>;
}

export const createCentralServer = (config: CentralServerConfig): CentralServer => {
  const { storage } = config;
  const devMode = config.devMode ?? (config.operatorToken === 'dev');
  // Auth mode: server-side default 'dev' (auth required) so unit tests
  // behave like production; main.ts overrides via authMode when the user
  // explicitly sets VAIVAR_CENTRAL_AUTH_MODE=none to disable auth.
  const requireAuth = (config.authMode ?? 'dev') !== 'none';
  const ingest = createBarrierAuth(config.ingestToken);
  const ingestKey = config.ingestToken ? deriveControlKey(config.ingestToken) : null;
  const seenIngestMessages = new Map<string, number>();
  const releaseCatalog: ReleaseCatalog | null = config.releaseDir ? createReleaseCatalog(config.releaseDir) : null;
  const trustProxy = config.trustProxy ?? false;
  const consoleDefense = new ConsoleDefense(config.defense ?? {});

  // ── Session + OIDC (authentication policy) ─────────────────
  // Humans carry ONE signed session cookie (`vaivar_session`). It is issued
  // after an OIDC login (Keycloak) or the bootstrap fallback. Machines keep
  // static barrier/ingest tokens and are resolved elsewhere — never as roles.
  const sessionKey = config.sessionKey || config.centralKey || 'vaivar-session-local';
  const sessionCtx: SessionContext = { sessionKey, devMode };
  // OIDC is optional: when not configured (no issuer), the console falls back
  // to legacy operator/admin/superadmin token login (lab/dev convenience).
  const oidcConfig = readOidcConfig();

  // Legacy token → role mapping used ONLY as a fallback when OIDC is absent.
  // operator token → user, admin token → admin, superadmin token → superadmin.
  const legacyTokenRoles: Array<{ token: string | undefined; role: Role; label: SessionAuth }> = [
    { token: config.superadminToken, role: 'superadmin', label: 'bootstrap' },
    { token: config.adminToken, role: 'admin', label: 'bootstrap' },
    { token: config.operatorToken, role: 'user', label: 'bootstrap' },
    { token: config.bootstrapToken, role: 'superadmin', label: 'bootstrap' },
  ];
  const findLegacyRole = (token: string): Role | null => {
    for (const entry of legacyTokenRoles) {
      if (entry.token && (token === entry.token.trim())) return entry.role;
    }
    return null;
  };

  const bootstrapHeader = (req: IncomingMessage): string | null => {
    const value = req.headers['x-vaivar-bootstrap-token'];
    return typeof value === 'string' ? value : null;
  };

  const validateNodeHost = (raw: string): { ok: true; host: string } | { ok: false; message: string } => {
    const host = raw.trim();
    if (!host) return { ok: false, message: 'Use a hostname or IPv4.' };
    if (host.includes('://') || host.includes('/') || host.includes('@') || /\s/.test(host) || host.includes(':')) {
      return { ok: false, message: 'Use a hostname or IPv4.' };
    }
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(host)
      && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      return { ok: false, message: 'Use a hostname or IPv4.' };
    }
    // SSRF guard: block loopback, RFC1918, link-local (incl. cloud metadata),
    // CGNAT, and multicast/reserved ranges — UNLESS the deployment explicitly
    // opted in to private addresses (Central and Edge on the same LAN/Docker).
    if (!config.allowPrivateHosts && !isPublicHost(host)) {
      return { ok: false, message: 'Node host must be a public address (private/loopback/metadata blocked). Use VAIVAR_ALLOW_PRIVATE_NODE_HOSTS=1 to allow private hosts.' };
    }
    return { ok: true, host };
  };

  /** Validate a user-supplied integration URL before any outbound fetch. */
  const validateIntegrationUrl = (url: unknown): { ok: true } | { ok: false; message: string } => {
    if (typeof url !== 'string' || url.trim().length === 0) {
      return { ok: false, message: 'config_json must include a non-empty "url" string.' };
    }
    const result = validateOutboundUrl(url.trim(), config.allowPrivateHosts ?? false);
    if (!result.ok) return { ok: false, message: result.message };
    return { ok: true };
  };

  const previewHits = new Map<string, number[]>();
  const allowPreview = (req: IncomingMessage): boolean => {
    const key = req.socket.remoteAddress || 'anon';
    const now = Date.now();
    const hits = (previewHits.get(key) || []).filter((t) => now - t < 60_000);
    if (hits.length >= 10) {
      previewHits.set(key, hits);
      return false;
    }
    hits.push(now);
    previewHits.set(key, hits);
    return true;
  };

  const writeJSON = (res: ServerResponse, status: number, body: unknown): void => {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(JSON.stringify(body));
  };

  const readBody = (req: IncomingMessage): Promise<string> =>
    new Promise((resolve) => {
      let body = '';
      req.on('data', (c) => (body += c.toString()));
      req.on('end', () => resolve(body));
      req.on('error', () => resolve(body));
    });

  const server = createServer(async (req, res) => {
    const url = req.url || '/';
    const method = req.method || 'GET';
    const path = url.split('?')[0];

    // Console self-defense: banned IPs get 429 on every endpoint except
    // /health (orchestrator liveness must keep working). Uniform response:
    // no hint about why they are blocked.
    const clientIp = ConsoleDefense.clientIp(req, trustProxy);
    if (path !== '/health' && consoleDefense.banned(clientIp)) {
      const secs = consoleDefense.banSecondsRemaining(clientIp);
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Retry-After': String(secs),
      });
      res.end(JSON.stringify({ error: 'Too many requests' }));
      return;
    }

    // RBAC: resolve the human caller once per request from the session cookie
    // (or devMode). It stays null when the request carries no valid credential
    // — the gate below enforces authentication except for public/bootstrap
    // routes. Permissions are a pure matrix keyed by the caller's role.
    let caller = resolveCaller(req, sessionCtx);
    // When auth is disabled, grant full access implicitly by faking a superadmin caller.
    if (!requireAuth) caller = { sub: 'anonymous', email: '', role: 'superadmin' as const, iat: 0, exp: 0, auth: 'dev' as const };

    const canRead = (): boolean => !!caller && can(caller.role, 'read');
    const canManageHoneypots = (): boolean => !!caller && can(caller.role, 'manage_honeypots');
    const canManageIntegrations = (): boolean => !!caller && can(caller.role, 'manage_integrations');
    // `manage_system` (superadmin-only) is reserved for future system routes
    // (release apply, data purge, central-key rotation). It remains in the
    // permission matrix so the superadmin role already carries it.

    // The logo is needed by the login page as well as the authenticated UI,
    // so serve this single public asset before any auth-gated route.
    if (path === VAIVAR_LOGO_URL && (method === 'GET' || method === 'HEAD')) {
      const logo = readVaivarLogoSvg();
      if (!logo) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('Logo not found');
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'image/svg+xml; charset=utf-8',
        'Cache-Control': 'public, max-age=86400',
        'X-Content-Type-Options': 'nosniff',
      });
      if (method === 'HEAD') {
        res.end();
        return;
      }
      res.end(logo);
      return;
    }

    // Health: orchestrator probe, no auth.
    if (path === '/health' && method === 'GET') {
      const stats = await storage.getStats();
      writeJSON(res, 200, { status: 'ok', uptime: process.uptime(), events: stats.events, version: VAIVAR_VERSION });
      return;
    }

    // CSP: defense-in-depth. All scripts/styles inlined by design (SPA);
    // the restrictive policy blocks script/eval injection paths if escaping
    // is ever bypassed. Only the inline default-src set; style/img strict.
    const CSP = "default-src 'none'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; font-src 'none'; connect-src 'self' http://localhost; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; upgrade-insecure-requests";

    const persistIngestBatch = async (batch: unknown): Promise<{ accepted: number; total: number }> => {
      const items = Array.isArray(batch) ? batch : [batch];
      let accepted = 0;
      for (const item of items) {
        const rec = item as { site_id?: string; payload?: Record<string, unknown> };
        if (!rec || typeof rec.site_id !== 'string' || !rec.payload) continue;
        const event = { ...(rec.payload as Record<string, unknown>), site_id: rec.site_id } as unknown as Event;
        await persistEvent(storage, event, config.openCTIConnectors);
        const rawTs = (event as unknown as { ts?: unknown }).ts;
        const originTs = typeof rawTs === 'string'
          ? new Date(rawTs).getTime()
          : (typeof rawTs === 'number' ? rawTs : Date.now());
        const eventId = (event as { id?: string }).id ?? `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        try {
          await storage.saveCentralEvent(
            rec.site_id,
            'default',
            eventId,
            String(originTs),
            originTs,
            event.type ?? 'unknown',
            rec.payload
          );
        } catch {
          // Best effort
        }
        accepted += 1;
      }
      return { accepted, total: items.length };
    };

    // Ingest: Edge -> central. New clients use an application-encrypted
    // envelope over HTTP. No token is present in the request headers.
    if (path === '/api/v1/events/secure' && method === 'POST') {
      if (!ingestKey) {
        writeJSON(res, 404, { error: 'Encrypted ingest is not configured' });
        return;
      }
      try {
        const envelope = JSON.parse(await readBody(req)) as unknown;
        const opened = openControlMessage<unknown>(ingestKey, 'request', envelope);
        const now = Date.now();
        for (const [key, seenAt] of seenIngestMessages) {
          if (now - seenAt > 10 * 60 * 1000) seenIngestMessages.delete(key);
        }
        const replayKey = controlEnvelopeReplayKey(opened.requestId, opened.nonce);
        if (seenIngestMessages.has(replayKey)) throw new Error('Replayed ingest message');
        seenIngestMessages.set(replayKey, now);
        const result = await persistIngestBatch(opened.payload);
        const logical: ControlResponse = { status: 200, body: JSON.stringify(result) };
        writeJSON(res, 200, sealControlMessage(ingestKey, 'response', opened.requestId, logical));
      } catch {
        writeJSON(res, 400, { error: 'Invalid encrypted ingest request' });
      }
      return;
    }

    // Legacy ingest: retained only for clients deployed before encrypted
    // event forwarding existed. New clients never use this route.
    if (path === '/api/v1/events' && method === 'POST') {
      if (!ingest.verify(bearerToken(req))) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const raw = await readBody(req);
      let batch: unknown;
      try {
        batch = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      writeJSON(res, 200, await persistIngestBatch(batch));
      return;
    }

    // CSP for all HTML responses (dashboard, login).
      res.setHeader('Content-Security-Policy', CSP);
    // Login page: GET shows form (no auth), POST validates and sets cookie.
    if (path === '/login' && method === 'GET') {
      // In dev mode or when auth is disabled, skip the login form entirely.
      if (devMode || !requireAuth) {
        res.writeHead(302, { Location: '/dashboard' });
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      const emergencyForm = `
<form id="f" style="margin-top:16px">
<p>Sign in with your account token (break-glass / fallback).</p>
<label for="t">Token</label><input id="t" type="password" placeholder="Account token" autocomplete="off"/>
<button type="submit">Sign in</button><div class="error" id="e"></div></form>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const t=document.getElementById('t').value;
const r=await fetch('/api/v1/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})});
if(r.ok){location='/overview'}else{document.getElementById('e').textContent='Invalid token'}});</script>`;
      const kcButton = oidcConfig
        ? `<form action="/api/v1/oidc/start" method="GET"><button type="submit" class="kc">Sign in with Keycloak</button></form><details class="emergency"><summary>Emergency token</summary>${emergencyForm}</details>`
        : emergencyForm;
      res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>vAIvar Login</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>body{background:#f8fafc;color:#1e293b;font-family:Inter,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:28px;width:360px;box-shadow:0 10px 15px -3px rgba(0,0,0,.06)}
h2{margin:0 0 6px;font-size:1.15rem}p{margin:0 0 18px;font-size:.8rem;color:#475569}
label{display:block;font-size:.75rem;font-weight:600;color:#475569;margin-bottom:5px}
input{width:100%;box-sizing:border-box;background:#fff;border:1px solid #e2e8f0;color:#1e293b;padding:10px;border-radius:6px;font-size:.85rem;margin-bottom:14px}
button{background:#6366f1;border:0;color:#fff;padding:10px 14px;border-radius:6px;cursor:pointer;font-weight:600;width:100%}
button.kc{background:#1f2937;margin-bottom:4px}
button:focus-visible,input:focus-visible{outline:2px solid #6366f1;outline-offset:2px}
.error{color:#e11d48;font-size:.8rem;margin-top:10px}
details.emergency{margin-top:18px;font-size:.8rem;color:#475569}summary{cursor:pointer}
@media (prefers-color-scheme: dark){body{background:#09090b;color:#f4f4f5}form{background:#121215;border-color:#222226}input{background:#121215;border-color:#333339;color:#f4f4f5}p,label,details.emergency{color:#a1a1aa}}</style></head><body>
<form id="x"><h2>vAIvar Central</h2></form>${kcButton}</body></html>`);
      return;
    }
    if (path === '/api/v1/login' && method === 'POST') {
      const raw = await readBody(req);
      let body: unknown;
      try { body = JSON.parse(raw); } catch { writeJSON(res, 400, { error: 'Invalid JSON' }); return; }
      const token = typeof (body as { token?: unknown })?.token === 'string' ? (body as { token: string }).token : null;
      if (!token) {
        consoleDefense.recordLoginFailure(clientIp);
        writeJSON(res, 401, { error: 'Invalid token' });
        return;
      }
      // When OIDC is configured, only the break-glass bootstrap token is
      // accepted here; normal humans use the Keycloak flow. When OIDC is NOT
      // configured, legacy operator/admin/superadmin tokens map to roles.
      const role = findLegacyRole(token);
      if (!role) {
        consoleDefense.recordLoginFailure(clientIp);
        writeJSON(res, 401, { error: 'Invalid token' });
        return;
      }
      consoleDefense.recordLoginSuccess(clientIp);
      const now = Math.floor(Date.now() / 1000);
      issueSessionCookie(res, sessionKey, {
        sub: 'bootstrap',
        email: 'bootstrap@local',
        role,
        iat: now,
        exp: now + 43200,
        auth: 'bootstrap',
      });
      writeJSON(res, 200, { ok: true, role });
      return;
    }

    // OIDC start: redirect to Keycloak's authorization endpoint (PKCE + state).
    if (path === '/api/v1/oidc/start' && method === 'GET') {
      if (!oidcConfig) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('OIDC not configured'); return; }
      try {
        const { url } = await buildAuthorizeUrl(oidcConfig);
        res.writeHead(302, { Location: url });
        res.end();
      } catch {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('OIDC start failed');
      }
      return;
    }

    // OIDC callback: exchange the code, verify id_token, issue a session cookie.
    if (path === '/api/v1/oidc/callback' && method === 'GET') {
      if (!oidcConfig) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('OIDC not configured'); return; }
      const query = new URL(req.url || '', 'http://localhost').searchParams;
      let identity: CallerIdentity | null = null;
      try {
        const result = await exchangeCode(oidcConfig, query);
        if (result) identity = result.identity;
      } catch { /* fall through to error redirect */ }
      if (!identity) {
        res.writeHead(302, { Location: '/login?error=1' });
        res.end();
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      issueSessionCookie(res, sessionKey, {
        sub: identity.sub,
        email: identity.email,
        role: identity.role,
        iat: now,
        exp: now + 43200,
        auth: 'oidc',
      });
      res.writeHead(302, { Location: '/overview' });
      res.end();
      return;
    }

    // OIDC logout: drop the Central session, then end the Keycloak session.
    if (path === '/api/v1/oidc/logout' && method === 'GET') {
      clearSessionCookie(res);
      if (oidcConfig) {
        try {
          const endUrl = await buildEndSessionUrl(oidcConfig, `${req.headers.origin || ''}/login`.replace('//login', '/login'));
          if (endUrl) { res.writeHead(302, { Location: endUrl }); res.end(); return; }
        } catch { /* fall through */ }
      }
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }

    // Central UI: operator web console (node list, enrollment form, node detail).
    // In devMode (dev token or devMode flag), the dashboard is public — no auth required.
    const isHtmlRequest = (req.headers.accept || '').includes('text/html');
    const isUIRoute = (
      path === '/' ||
      path === '/dashboard' ||
      path === '/overview' ||
      path === '/honeypots' ||
      path === '/nodes' ||
      path === '/threats' ||
      path === '/sessions' ||
      (path.startsWith('/nodes/') && !path.startsWith('/api/')) ||
      ((path === '/activity' || path === '/settings') && (isHtmlRequest || !req.headers.accept || req.headers.accept === '*/*'))
    );

    if (isUIRoute && method === 'GET') {
      if (requireAuth && !devMode && !caller) {
        res.writeHead(302, { Location: '/login' });
        res.end();
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': CSP,
        'Cache-Control': 'no-store',
      });
      res.end(renderCentralDashboardHTML(VAIVAR_VERSION));
      return;
    }

// Auth check endpoint: returns whether a session is authenticated.
    if (path === '/auth-check' && method === 'GET') {
      writeJSON(res, caller ? 200 : 401, { authenticated: !!caller, role: caller?.role ?? null });
      return;
    }

    // Logout: clear the session cookie.
    if ((path === '/api/v1/logout' || path === '/logout') && method === 'POST') {
      clearSessionCookie(res);
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // RBAC gate: unauthenticated requests to non-public routes get 401.
    // Bootstrap endpoints authenticate via a single-use capability
    // instead of an account credential.
    if (requireAuth && !caller && !path.startsWith('/api/v1/bootstrap/')) {
      // Console self-defense: repeated 401s are credential probing.
      consoleDefense.recordApiProbeFailure(clientIp);
      writeJSON(res, 401, { error: 'Unauthorized' });
      return;
    }

    // Prometheus metrics for Grafana: aggregated by site and attacker IP.
    if (path === '/metrics' && method === 'GET') {
      const attackers = await storage.getAttackers(500);
      const eventsBySite = await storage.getEventsBySite();
      const flagsBySite = await storage.getFlagsBySite();
      const activityBySite = await storage.getActivityBySite();
      const stats = await storage.getStats();

      // Escape Prometheus label values: strip characters that corrupt
      // exposition or allow label injection ("`, `{`, `}`) or CRLF.
      const safeLabel = (v: string | null | undefined): string =>
        (v ?? '').replace(/["\\\n\r{}]/g, '\\$&');

      const metrics: string[] = [
        '# HELP vaivar_attackers_by_site_ip Unique attacker IPs observed per site',
        '# TYPE vaivar_attackers_by_site_ip gauge',
        ...attackers.map((a) => `vaivar_attackers_by_site_ip{site_id="${safeLabel(a.site_id)}",ip="${safeLabel(a.ip)}"} ${a.count}`),
        '# HELP vaivar_events_total Events received per site',
        '# TYPE vaivar_events_total counter',
        ...eventsBySite.map((e) => `vaivar_events_total{site_id="${safeLabel(e.site_id)}"} ${e.count}`),
        '# HELP vaivar_flags_total Flags triggered per site',
        '# TYPE vaivar_flags_total counter',
        ...flagsBySite.map((f) => `vaivar_flags_total{site_id="${safeLabel(f.site_id)}"} ${f.count}`),
        '# HELP vaivar_attacker_activity_total Attacker activity records per site',
        '# TYPE vaivar_attacker_activity_total counter',
        ...activityBySite.map((a) => `vaivar_attacker_activity_total{site_id="${safeLabel(a.site_id)}"} ${a.count}`),
        '# HELP vaivar_storage_bytes Current storage size in bytes',
        '# TYPE vaivar_storage_bytes gauge',
        `vaivar_storage_bytes ${stats.size_bytes}`,
        '# HELP vaivar_uptime_seconds Service uptime in seconds',
        '# TYPE vaivar_uptime_seconds gauge',
        `vaivar_uptime_seconds ${process.uptime().toFixed(2)}`,
        // Console self-defense counters (Grafana alerting on these).
        '# HELP vaivar_console_attackers_total Distinct IPs tracked by console defense',
        '# TYPE vaivar_console_attackers_total gauge',
        `vaivar_console_attackers_total ${consoleDefense.snapshot().length}`,
        '# HELP vaivar_console_banned_ips Currently banned IPs',
        '# TYPE vaivar_console_banned_ips gauge',
        `vaivar_console_banned_ips ${consoleDefense.bannedCount()}`,
      ];

      // Optional: Splunk HEC export metrics (bounded labels: sent/failed/queued/enabled).
      if (config.splunkHec && config.splunkHec.enabled) {
        const h = config.splunkHec.getStatistics();
        metrics.push(
          '# HELP vaivar_splunk_hec_sent_total Events forwarded to Splunk HEC',
          '# TYPE vaivar_splunk_hec_sent_total counter',
          `vaivar_splunk_hec_sent_total${h.destination ? ` {destination="${h.destination}"}` : ''} ${h.sent_count}`,
          '# HELP vaivar_splunk_hec_failed_total Export attempts that failed after retries',
          '# TYPE vaivar_splunk_hec_failed_total counter',
          `vaivar_splunk_hec_failed_total${h.destination ? ` {destination="${h.destination}"}` : ''} ${h.failed_count}`,
          '# HELP vaivar_splunk_hec_queued gauge',
          '# TYPE vaivar_splunk_hec_queued gauge',
          `vaivar_splunk_hec_queued${h.destination ? ` {destination="${h.destination}"}` : ''} ${h.queued_count}`,
          '# HELP vaivar_splunk_hec_enabled Whether the Splunk HEC adapter is enabled',
          '# TYPE vaivar_splunk_hec_enabled gauge',
          `vaivar_splunk_hec_enabled ${h.enabled ? 1 : 0}`
        );
      }

      const output = metrics.join('\n');

      res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
      res.end(output);
      return;
    }

      if (path === '/api/v1/dashboard' && method === 'GET') {
        const stats = await storage.getStats();
        writeJSON(res, 200, { overview: stats, uptime: process.uptime() });
        return;
      }

    if (path === '/api/v1/me' && method === 'GET') {
      // Caller identity + permission list for UI gating. The UI uses this to
      // hide actions (manage_honeypots / manage_integrations / manage_system)
      // from roles that don't have them. `auth` tells the UI if the session
      // came from OIDC, the bootstrap token, or dev mode.
      const perms: readonly string[] = caller ? ROLE_PERMISSIONS[caller.role] : [];
      writeJSON(res, 200, {
        role: caller?.role ?? null,
        email: caller?.email ?? null,
        sub: caller?.sub ?? null,
        dev_mode: devMode,
        auth: caller?.auth ?? null,
        permissions: perms.slice(),
      });
      return;
    }

    // Stats endpoint for UI Overview.
    if ((path === '/stats' || path === '/api/v1/stats') && method === 'GET') {
      const stats = await storage.getStats();
      let nodeCount = 0;
      if (config.nodeRegistry) {
        const nodes = await config.nodeRegistry.listNodes().catch(() => []);
        nodeCount = nodes.length;
      }
      writeJSON(res, 200, {
        nodes: nodeCount,
        events: stats.events ?? 0,
        flags: stats.flags ?? 0,
        sessions: stats.sessions ?? 0,
        size_bytes: stats.size_bytes ?? 0,
        attacker_activity: stats.attacker_activity ?? 0,
        event_envelopes: stats.event_envelopes ?? 0,
        uptime_seconds: process.uptime(),
        version: VAIVAR_VERSION,
      });
      return;
    }

    // Events endpoint for UI Activity.
    if ((path === '/events' || path === '/api/v1/events') && method === 'GET') {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') ?? '50', 10) || 50, 1), 500);
      const siteId = url.searchParams.get('site_id');
      const central = await storage.listCentralEvents(siteId ?? null, limit + 1);
      const hasMore = central.length > limit;
      const page = hasMore ? central.slice(0, limit) : central;
      const events = page.map((c) => {
        const payload = (typeof c.payload === 'object' && c.payload !== null) ? (c.payload as Record<string, unknown>) : null;
        const sessionId =
          payload !== null && typeof payload.session_id === 'string'
            ? payload.session_id
            : null;

        let summary = '';
        let severity = 'info';
        let attackerIp: string | null = null;
        let classification: string | null = null;
        let tooling: string[] = [];
        let trapPath: string | null = null;
        let flagCode: string | null = null;
        let flagLevel: number | null = null;

        const isFlag = c.event_type === 'flag.hit' || (payload && payload.type === 'flag.hit');
        const isSession = c.event_type === 'session.upsert' || (payload && payload.type === 'session.upsert');

        if (isFlag) {
          const flag = (payload?.flag as { code?: string; level?: number }) ?? null;
          const context = (payload?.context as { skin?: string; node_id?: string; hint?: string }) ?? null;
          flagCode = flag?.code ?? 'FLAG_HIT';
          flagLevel = flag?.level ?? null;
          trapPath = context?.node_id ?? null;
          const skin = context?.skin ?? 'unknown';
          const hint = context?.hint ?? '';
          severity = flagCode === 'FLAG_WIN' ? 'critical' : (flagLevel && flagLevel >= 2 ? 'high' : 'medium');
          summary = `Compromise Trap Triggered: [${flagCode}${flagLevel ? ` · Level ${flagLevel}` : ''}] on skin "${skin}" at target "${trapPath || 'unknown'}". ${hint ? `Evidence: ${hint}` : 'Tripwire fired.'}`;
        } else if (isSession) {
          const agent = (payload?.agent as { class?: string; tooling?: string[]; confidence?: number }) ?? null;
          const src = (payload?.src as { ip?: string; userAgent?: string }) ?? null;
          const progress = (payload?.progress as { level_max?: number }) ?? null;
          attackerIp = src?.ip ?? null;
          classification = agent?.class ?? null;
          tooling = Array.isArray(agent?.tooling) ? agent.tooling : [];
          severity = (payload?.severity_hint as string) ?? 'low';
          const conf = agent?.confidence ? `${Math.round(agent.confidence * 100)}%` : null;
          const toolStr = tooling.length ? `Tools: [${tooling.join(', ')}]` : '';
          const maxLvl = progress?.level_max ? `Max level: ${progress.level_max}` : '';
          summary = `Hostile Probe: Class "${classification || 'unknown'}"${conf ? ` (${conf} confidence)` : ''} from IP ${attackerIp || 'hidden'}. ${toolStr} ${maxLvl}`.trim();
        } else if (c.event_type.includes('canary')) {
          severity = 'high';
          summary = `Canary Token Triggered: Honeytoken breached or exfiltrated.`;
        } else if (c.event_type.includes('command')) {
          summary = `Honeypot Command: ${c.event_type}`;
        } else {
          summary = `Event [${c.event_type}] logged for session ${sessionId || 'n/a'}`;
        }

        return {
          ts: c.ts,
          type: c.event_type,
          site_id: c.site_id,
          stream_id: c.stream_id,
          sequence: c.sequence,
          payload,
          session_id: sessionId,
          summary,
          severity,
          attacker_ip: attackerIp,
          classification,
          tooling,
          trap_path: trapPath,
          flag_code: flagCode,
          flag_level: flagLevel,
        };
      });
      writeJSON(res, 200, { events, has_more: hasMore });
      return;
    }

    // Settings endpoint for UI Settings.
    if ((path === '/settings' || path === '/api/v1/settings') && method === 'GET') {
      writeJSON(res, 200, {
        operator_token_masked: config.operatorToken ? '***' + config.operatorToken.slice(-4) : '',
        admin_token_masked: config.adminToken ? '***' + config.adminToken.slice(-4) : '',
        retention_days: 90,
      });
      return;
    }
    if ((path === '/settings' || path === '/api/v1/settings') && method === 'POST') {
      const raw = await readBody(req);
      let body: unknown;
      try { body = JSON.parse(raw); } catch { writeJSON(res, 400, { error: 'Invalid JSON' }); return; }
      const parsed = body as Record<string, unknown>;
      const retentionDays = typeof parsed.retentionDays === 'number' ? parsed.retentionDays : 90;
      writeJSON(res, 200, { ok: true, retentionDays });
      return;
    }

    // --- Integrations management (operator). --------------------------------
    if (path === '/api/v1/integrations' && method === 'GET') {
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const integrations = await storage.listIntegrationSettings();
      writeJSON(res, 200, { integrations });
      return;
    }

     if (path === '/api/v1/integrations' && method === 'POST') {
      if (!canManageIntegrations()) {
        writeJSON(res, caller ? 403 : 401, { error: 'Forbidden: admin required to manage integrations' });
        return;
      }
      const raw = await readBody(req);
      let body: unknown;
      try { body = JSON.parse(raw); } catch { writeJSON(res, 400, { error: 'Invalid JSON' }); return; }
      const parsed = body as { name: string; kind: IntegrationKind; label: string; config_json: string };
      if (!parsed?.name || typeof parsed.name !== 'string' || parsed.name.trim().length === 0) {
        writeJSON(res, 400, { error: 'name is required' });
        return;
      }
      if (!parsed?.kind || !['cti', 'siem', 'topology', 'metrics', 'dashboard'].includes(parsed.kind)) {
        writeJSON(res, 400, { error: 'kind must be one of: cti, siem, topology, metrics, dashboard' });
        return;
      }
      if (!parsed?.label || typeof parsed.label !== 'string') {
        writeJSON(res, 400, { error: 'label is required' });
        return;
      }
      if (!parsed?.config_json || typeof parsed.config_json !== 'string') {
        writeJSON(res, 400, { error: 'config_json is required' });
        return;
      }
      // SSRF guard: validate the integration URL before persisting it.
      let cfgProbe: { url?: unknown } = {};
      try { cfgProbe = JSON.parse(parsed.config_json) as { url?: unknown }; }
      catch { writeJSON(res, 400, { error: 'config_json must be valid JSON' }); return; }
      const urlCheck = validateIntegrationUrl(cfgProbe.url);
      if (!urlCheck.ok) {
        writeJSON(res, 400, { error: urlCheck.message });
        return;
      }
      await storage.saveIntegrationSetting({
        name: parsed.name.trim(),
        kind: parsed.kind,
        label: parsed.label,
        config_json: parsed.config_json,
        enabled: 0,
        verified_at_ms: null,
        tested_at_ms: null,
        last_error: null,
        updated_at_ms: Date.now(),
      });
      writeJSON(res, 200, { ok: true, name: parsed.name.trim() });
      return;
    }

    // ── Human account management lives in Keycloak (
    // authentication policy). Roles are granted by Keycloak group
    // membership (vaivar-viewer/user/admin/superadmin); Central never stores
    // users or passwords. There is intentionally NO /api/v1/accounts CRUD.

    const integrationMatch = path.match(/^\/api\/v1\/integrations\/([^/]+)$/);
    if (integrationMatch && method === 'GET') {
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const setting = await storage.getIntegrationSetting(integrationMatch[1]);
      if (!setting) {
        writeJSON(res, 404, { error: 'Integration not found' });
        return;
      }
      writeJSON(res, 200, setting);
      return;
    }

    if (integrationMatch && method === 'DELETE') {
      if (!canManageIntegrations()) {
        writeJSON(res, caller ? 403 : 401, { error: 'Forbidden: admin required' });
        return;
      }
      const removed = await storage.deleteIntegrationSetting(integrationMatch[1]);
      if (!removed) {
        writeJSON(res, 404, { error: 'Integration not found' });
        return;
      }
      writeJSON(res, 200, { ok: true, name: integrationMatch[1] });
      return;
    }

    const testMatch = path.match(/^\/api\/v1\/integrations\/([^/]+)\/test$/);
    if (testMatch && method === 'POST') {
      if (!canManageIntegrations()) {
        writeJSON(res, caller ? 403 : 401, { error: 'Forbidden: admin required' });
        return;
      }
      const setting = await storage.getIntegrationSetting(testMatch[1]);
      if (!setting) {
        writeJSON(res, 404, { error: 'Integration not found' });
        return;
      }
      let cfg: any;
      try { cfg = JSON.parse(setting.config_json); } catch {
        writeJSON(res, 400, { error: 'Invalid config_json' });
        return;
      }
      let testOk = false;
      let lastError: string | null = null;
      if (setting.kind === 'cti') {
        try {
          const response = await fetch(`${cfg.url.replace(/\/$/, '')}/api/v1/status`, {
            headers: { Authorization: `Bearer ${cfg.token}` },
            signal: AbortSignal.timeout(10000),
            redirect: 'manual',
          });
          testOk = response.ok;
        } catch (e) {
          lastError = e instanceof Error ? e.message : 'connection failed';
        }
      } else if (setting.kind === 'siem') {
        try {
          const response = await fetch(`${cfg.url.replace(/\/$/, '')}/services/collector`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Splunk ${cfg.token}`,
            },
            body: '{"events":[{"time":"1234567890","host":"localhost","index":"test","sourcetype":"test","source":"test","event":"healthcheck"}]}',
            signal: AbortSignal.timeout(10000),
            redirect: 'manual',
          });
          testOk = response.ok || response.status === 400; // 400 may be index/auth error but URL reachable
        } catch (e) {
          lastError = e instanceof Error ? e.message : 'connection failed';
        }
      } else if (setting.kind === 'metrics') {
        try {
          const response = await fetch(`${cfg.url.replace(/\/$/, '')}/api/prometheus`, {
            method: 'HEAD',
            headers: { Authorization: `Bearer ${cfg.token}` },
            signal: AbortSignal.timeout(10000),
            redirect: 'manual',
          });
          testOk = response.ok;
        } catch (e) {
          lastError = e instanceof Error ? e.message : 'connection failed';
        }
      } else if (setting.kind === 'dashboard') {
        try {
          const response = await fetch(`${cfg.url.replace(/\/$/, '')}/api/dashboards`, {
            headers: { Authorization: `Bearer ${cfg.token}` },
            signal: AbortSignal.timeout(10000),
            redirect: 'manual',
          });
          testOk = response.ok;
        } catch (e) {
          lastError = e instanceof Error ? e.message : 'connection failed';
        }
      }
      await storage.saveIntegrationSetting({
        ...setting,
        tested_at_ms: Date.now(),
        last_error: lastError,
        verified_at_ms: testOk ? Date.now() : setting.verified_at_ms,
      });
      writeJSON(res, 200, { ok: testOk, test_ok: testOk, error: lastError });
      return;
    }

    const enableMatch = path.match(/^\/api\/v1\/integrations\/([^/]+)\/enable$/);
    if (enableMatch && method === 'POST') {
      if (!canManageIntegrations()) {
        writeJSON(res, caller ? 403 : 401, { error: 'Forbidden: admin required' });
        return;
      }
      const setting = await storage.getIntegrationSetting(enableMatch[1]);
      if (!setting) {
        writeJSON(res, 404, { error: 'Integration not found' });
        return;
      }
      await storage.saveIntegrationSetting({ ...setting, enabled: setting.enabled ? 0 : 1, updated_at_ms: Date.now() });
      writeJSON(res, 200, { enabled: setting.enabled ? 0 : 1 });
      return;
    }

    if ((path === '/activity' || path === '/api/v1/activity' || path === '/api/v1/activity/') && method === 'GET') {
      const activity = await storage.listAttackerActivity(null, 500);
      writeJSON(res, 200, { session_id: null, count: activity.length, activity });
      return;
    }

    if (path === '/api/v1/exports/splunk' && method === 'GET') {
      if (!config.splunkHec) {
        writeJSON(res, 404, { error: 'Splunk HEC adapter not configured' });
        return;
      }
      writeJSON(res, 200, {
        destination: config.splunkHec.getStatistics(),
        delivery: await storage.listExportDeliveries(),
      });
      return;
    }

    const activityMatch = path.match(/^\/api\/v1\/activity\/([^/]+)$/);
    if (activityMatch && method === 'GET') {
      const activity = await storage.listAttackerActivity(activityMatch[1], 500);
      writeJSON(res, 200, { session_id: activityMatch[1], count: activity.length, activity });
      return;
    }

    const parseNodeRegistration = (parsed: unknown): NodeRegistrationRequest | { error: string; code: 'invalid' } => {
    const body = parsed as Partial<NodeRegistrationRequest>;
      if (
        typeof body?.host !== 'string' ||
        typeof body?.port !== 'number' || !Number.isInteger(body.port) ||
        body.port < 1 || body.port > 65535 ||
        typeof body?.token !== 'string' || body.token.trim().length < 16
      ) {
        return { error: 'host, port (1-65535) and token (>=16 chars) are required', code: 'invalid' };
      }
      const hostCheck = validateNodeHost(body.host);
      if (!hostCheck.ok) return { error: hostCheck.message, code: 'invalid' };
      const tls = body.tls === undefined ? 'http' : body.tls;
      if (tls !== 'http') {
        return { error: 'Honeypot control transport must be HTTP; application encryption is used inside the protocol', code: 'invalid' };
      }
      const channel = body.channel === undefined ? 'encrypted' : body.channel;
      if (channel !== 'encrypted' && channel !== 'legacy') {
        return { error: 'channel must be encrypted or legacy', code: 'invalid' };
      }
      return {
        host: hostCheck.host,
        port: body.port,
        token: body.token.trim(),
        tls,
        channel,
      };
    };

    // Release metadata is operator-readable. The artifact itself is only
    // downloadable with a short-lived bootstrap token, so publishing the
    // catalog does not turn the central dashboard into an unauthenticated
    // package mirror.
    if (path === '/api/v1/releases' && method === 'GET') {
      if (!releaseCatalog) {
        writeJSON(res, 503, { error: 'Release catalog not configured' });
        return;
      }
      const releases = releaseCatalog.list().map((manifest) => ({
        schema: manifest.schema,
        version: manifest.version,
        channel: manifest.channel,
        sha256: manifest.sha256,
        size_bytes: manifest.size_bytes,
        created_at_ms: manifest.created_at_ms,
        signature: manifest.signature ?? null,
      }));
      writeJSON(res, 200, { current: releaseCatalog.current(), releases });
      return;
    }

    // A bootstrap token is issued by an admin, then used by the installer to
    // retrieve exactly the current central-approved bundle and enroll the
    // freshly started node. It is never accepted in Authorization: Bearer.
    if (path === '/api/v1/bootstrap/tokens' && method === 'POST') {
      if (!canManageHoneypots()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown = {};
      if (raw.trim()) {
        try {
          parsed = JSON.parse(raw);
        } catch {
          writeJSON(res, 400, { error: 'Invalid JSON' });
          return;
        }
      }
      const body = parsed as { ttl_seconds?: unknown; metadata?: unknown };
      if (body.ttl_seconds !== undefined && (typeof body.ttl_seconds !== 'number' || !Number.isFinite(body.ttl_seconds))) {
        writeJSON(res, 400, { error: 'ttl_seconds must be a finite number' });
        return;
      }
      const metadataRaw = body.metadata;
      let metadata: import('../storage/types').BootstrapTokenMetadata = {};
      if (metadataRaw && typeof metadataRaw === 'object') {
        const candidate = metadataRaw as Record<string, unknown>;
        if (typeof candidate.host === 'string') {
          const hostCheck = validateNodeHost(candidate.host);
          if (hostCheck.ok) metadata = { ...metadata, host: hostCheck.host };
        }
        if (typeof candidate.control_port === 'number' && Number.isInteger(candidate.control_port)
          && candidate.control_port >= 1 && candidate.control_port <= 65535) {
          metadata = { ...metadata, control_port: candidate.control_port };
        }
        if (typeof candidate.honeypot_port === 'number' && Number.isInteger(candidate.honeypot_port)
          && candidate.honeypot_port >= 1 && candidate.honeypot_port <= 65535) {
          metadata = { ...metadata, honeypot_port: candidate.honeypot_port };
        }
        if (isHoneypotProfile(candidate.profile)) metadata = { ...metadata, profile: candidate.profile };
        if (typeof candidate.template_id === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(candidate.template_id)) {
          metadata = { ...metadata, template_id: candidate.template_id };
        }
        if (typeof candidate.install_dir === 'string' && /^\/[A-Za-z0-9._/-]+$/.test(candidate.install_dir)) {
          metadata = { ...metadata, install_dir: candidate.install_dir };
        }
        if (typeof candidate.compose_project === 'string' && /^[a-z0-9][a-z0-9_-]{0,62}$/.test(candidate.compose_project)) {
          metadata = { ...metadata, compose_project: candidate.compose_project };
        }
        if (typeof candidate.site_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(candidate.site_id)) {
          metadata = { ...metadata, site_id: candidate.site_id };
        }
      }
      const issued = await storage.issueBootstrapToken(
        body.ttl_seconds === undefined ? 900 : Number(body.ttl_seconds),
        metadata,
      );
      writeJSON(res, 201, {
        bootstrap_token: issued.token,
        expires_at_ms: issued.expires_at_ms,
        release_download: '/api/v1/bootstrap/releases/current/download',
        registration: '/api/v1/bootstrap/register',
      });
      return;
    }

    if (path === '/api/v1/bootstrap/releases/current' && method === 'GET') {
      if (!releaseCatalog) {
        writeJSON(res, 503, { error: 'Release catalog not configured' });
        return;
      }
      if (!await storage.verifyBootstrapToken(bootstrapHeader(req) ?? '')) {
        writeJSON(res, 401, { error: 'Invalid or expired bootstrap token' });
        return;
      }
      const manifest = releaseCatalog.current();
      if (!manifest) {
        writeJSON(res, 404, { error: 'No stable release is published' });
        return;
      }
      writeJSON(res, 200, { manifest });
      return;
    }

    if (path === '/api/v1/bootstrap/releases/current/download' && method === 'GET') {
      if (!releaseCatalog) {
        writeJSON(res, 503, { error: 'Release catalog not configured' });
        return;
      }
      if (!await storage.verifyBootstrapToken(bootstrapHeader(req) ?? '')) {
        writeJSON(res, 401, { error: 'Invalid or expired bootstrap token' });
        return;
      }
      const manifest = releaseCatalog.current();
      if (!manifest) {
        writeJSON(res, 404, { error: 'No stable release is published' });
        return;
      }
      let artifactPath: string;
      let stat: fs.Stats;
      try {
        artifactPath = releaseCatalog.artifactPath(manifest);
        if (!fs.lstatSync(artifactPath).isFile()) throw new Error('artifact is not a regular file');
        stat = fs.statSync(artifactPath);
      } catch {
        writeJSON(res, 503, { error: 'Published release artifact is unavailable' });
        return;
      }
      if (!stat.isFile() || stat.size !== manifest.size_bytes) {
        writeJSON(res, 503, { error: 'Published release artifact failed integrity checks' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/gzip',
        'Content-Length': String(stat.size),
        'Content-Disposition': `attachment; filename="${manifest.artifact}"`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Vaivar-Release-Version': manifest.version,
        'X-Vaivar-Release-Sha256': manifest.sha256,
      });
      const stream = fs.createReadStream(artifactPath);
      stream.on('error', () => {
        if (!res.headersSent) writeJSON(res, 503, { error: 'Unable to read release artifact' });
        else res.destroy();
      });
      stream.pipe(res);
      return;
    }

    if (path === '/api/v1/bootstrap/installer' && method === 'GET') {
      if (!config.installerPath) {
        writeJSON(res, 503, { error: 'Bootstrap installer is not configured' });
        return;
      }
      if (!await storage.verifyBootstrapToken(bootstrapHeader(req) ?? '')) {
        writeJSON(res, 401, { error: 'Invalid or expired bootstrap token' });
        return;
      }
      let stat: fs.Stats;
      try {
        stat = fs.statSync(config.installerPath);
      } catch {
        writeJSON(res, 503, { error: 'Bootstrap installer is unavailable' });
        return;
      }
      if (!stat.isFile()) {
        writeJSON(res, 503, { error: 'Bootstrap installer is unavailable' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Length': String(stat.size),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Disposition': 'attachment; filename="honeypot-install.sh"',
      });
      const stream = fs.createReadStream(config.installerPath);
      stream.on('error', () => {
        if (!res.headersSent) writeJSON(res, 503, { error: 'Unable to read bootstrap installer' });
        else res.destroy();
      });
      stream.pipe(res);
      return;
    }

    if (path === '/api/v1/bootstrap/register' && method === 'POST') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      const token = bootstrapHeader(req);
      if (!await storage.verifyBootstrapToken(token ?? '')) {
        writeJSON(res, 401, { error: 'Invalid or expired bootstrap token' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      const reqBody = parseNodeRegistration(parsed);
      if ('error' in reqBody) {
        writeJSON(res, 400, { error: reqBody.error, code: reqBody.code });
        return;
      }
      try {
        const result = await config.nodeRegistry.enroll(reqBody);
        if (!result) {
          writeJSON(res, 422, { error: 'Node could not be verified with the provided token', code: 'invalid' });
          return;
        }
        if (!await storage.consumeBootstrapToken(token ?? '')) {
          writeJSON(res, 409, { error: 'Bootstrap token was already consumed', code: 'bootstrap_token_used' });
          return;
        }
        writeJSON(res, 201, { ...result, bootstrap_consumed: true });
      } catch (err) {
        if (err instanceof DuplicateNodeError) {
          writeJSON(res, 409, { error: 'Honeypot already registered', code: err.code, existing_site_id: err.existing_site_id });
          return;
        }
        throw err;
      }
      return;
    }

    if (path === '/api/v1/nodes/preview' && method === 'POST') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canManageHoneypots()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      if (!allowPreview(req)) {
        writeJSON(res, 429, { error: 'Too many preview attempts', code: 'rate_limited' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      const reqBody = parseNodeRegistration(parsed);
      if ('error' in reqBody) {
        writeJSON(res, 400, { error: reqBody.error, code: reqBody.code });
        return;
      }
      const preview = await config.nodeRegistry.previewIdentity(reqBody);
      console.log(`node preview host=${reqBody.host} port=${reqBody.port} channel=${reqBody.channel ?? 'encrypted'} code=${preview.ok ? 'ok' : preview.code}`);
      if (!preview.ok) {
        writeJSON(res, 422, { ok: false, error: preview.message, code: preview.code });
        return;
      }
      const identity = preview.identity;
      writeJSON(res, 200, {
        ok: true,
        site_id: identity.site_id,
        api_version: identity.api_version,
        boot_id: identity.boot_id,
        stream_id: identity.stream_id,
        challenge_generation: identity.challenge_generation,
        capabilities: identity.capabilities,
        control_port: identity.control_port ?? reqBody.port,
        honeypot_port: identity.honeypot_port ?? null,
        service_profile: identity.service_profile ?? null,
        template_id: identity.template_id ?? null,
        template_version: identity.template_version ?? null,
        control_tls: identity.control_tls ?? reqBody.tls,
        control_channel: identity.control_channel ?? reqBody.channel,
        duplicate: preview.duplicate,
        existing_site_id: preview.duplicate ? identity.site_id : null,
      });
      return;
    }

    // Declarative public-surface template catalog. Template bodies are only
    // accepted from an authenticated admin and are validated before storage;
    // operators can list/read them but cannot publish content.
    const templateMatch = path.match(/^\/api\/v1\/templates(?:\/([^/]+))?$/);
    if (templateMatch && method === 'GET') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      if (templateMatch[1]) {
        const template = await storage.getHoneypotTemplate(decodeURIComponent(templateMatch[1]));
        if (!template) {
          writeJSON(res, 404, { error: 'Template not found' });
          return;
        }
        writeJSON(res, 200, { template });
        return;
      }
      const templates = await storage.listHoneypotTemplates();
      writeJSON(res, 200, {
        templates: templates.map(({ template_json, ...summary }) => summary),
      });
      return;
    }

    if (path === '/api/v1/templates' && method === 'POST') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canManageHoneypots()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      const checked = validateHoneypotTemplate(parsed);
      if (!checked.ok) {
        writeJSON(res, 400, { error: checked.error });
        return;
      }
      const record = await storage.saveHoneypotTemplate(checked.template);
      writeJSON(res, 201, { template: checked.template, version: record.version, updated_at_ms: record.updated_at_ms });
      return;
    }

    // --- Node registration (admin only). ---
    if (path === '/api/v1/nodes' && method === 'POST') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canManageHoneypots()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      const reqBody = parseNodeRegistration(parsed);
      if ('error' in reqBody) {
        writeJSON(res, 400, { error: reqBody.error, code: reqBody.code });
        return;
      }
      try {
        const result = await config.nodeRegistry.enroll(reqBody);
        console.log(`node enroll host=${reqBody.host} port=${reqBody.port} channel=${reqBody.channel ?? 'encrypted'} code=${result ? 'ok' : 'invalid'}`);
        if (!result) {
          writeJSON(res, 422, { error: 'Node could not be verified with the provided token', code: 'invalid' });
          return;
        }
        writeJSON(res, 201, result);
      } catch (err) {
        if (err instanceof DuplicateNodeError) {
          writeJSON(res, 409, { error: 'Honeypot already registered', code: err.code, existing_site_id: err.existing_site_id });
          return;
        }
        throw err;
      }
      return;
    }

    // List nodes (operator role; secrets never included).
    if (path === '/api/v1/nodes' && method === 'GET') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const nodes = await config.nodeRegistry.listNodes();
      writeJSON(res, 200, { nodes: nodes.map(({ encrypted_secret, iv, auth_tag, encrypted_secret_aad, ...safe }) => safe) });
      return;
    }

    const nodeMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)$/);
    if (nodeMatch && method === 'GET') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const node = await config.nodeRegistry.getNode(nodeMatch[1]);
      if (!node) {
        writeJSON(res, 404, { error: 'Node not found' });
        return;
      }
      const { encrypted_secret, iv, auth_tag, encrypted_secret_aad, ...safe } = node;
      writeJSON(res, 200, safe);
      return;
    }

    const nodeMetaMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)\/metadata$/);
    if (nodeMetaMatch && (method === 'POST' || method === 'PATCH')) {
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      const body = parsed as { name?: string | null; notes?: string | null };
      const siteId = nodeMetaMatch[1];
      const updated = await storage.updateCentralNodeMetadata(siteId, {
        name: body.name !== undefined ? (typeof body.name === 'string' ? body.name.trim() : null) : undefined,
        notes: body.notes !== undefined ? (typeof body.notes === 'string' ? body.notes.trim() : null) : undefined,
      });
      if (!updated) {
        writeJSON(res, 404, { error: 'Node not found' });
        return;
      }
      const node = await storage.getCentralNode(siteId);
      writeJSON(res, 200, { ok: true, site_id: siteId, name: node?.name ?? null, notes: node?.notes ?? null });
      return;
    }

    if (nodeMatch && method === 'DELETE') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canManageHoneypots() && !devMode) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      await config.nodeRegistry.removeNode(nodeMatch[1]);
      writeJSON(res, 200, { ok: true, removed: nodeMatch[1] });
      return;
    }

    // Pending token change: verify the new token before activation.
    if (nodeMatch && method === 'PATCH') {
      if (!config.nodeRegistry) {
        writeJSON(res, 503, { error: 'Node registry not configured' });
        return;
      }
      if (!canRead()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const raw = await readBody(req);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        writeJSON(res, 400, { error: 'Invalid JSON' });
        return;
      }
      const body = parsed as { token?: string; channel?: unknown; name?: string | null; notes?: string | null };
      if (body.name !== undefined || body.notes !== undefined) {
        await storage.updateCentralNodeMetadata(nodeMatch[1], {
          name: typeof body.name === 'string' ? body.name.trim() : (body.name === null ? null : undefined),
          notes: typeof body.notes === 'string' ? body.notes.trim() : (body.notes === null ? null : undefined),
        });
        if (typeof body.token !== 'string') {
          const node = await storage.getCentralNode(nodeMatch[1]);
          writeJSON(res, 200, { ok: true, site_id: nodeMatch[1], name: node?.name ?? null, notes: node?.notes ?? null });
          return;
        }
      }
      if (!canManageHoneypots() && !devMode) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      if (typeof body?.token !== 'string' || body.token.length < 16) {
        writeJSON(res, 400, { error: 'token (>=16 chars) required for pending verification' });
        return;
      }
      if (body.channel !== undefined && body.channel !== 'encrypted' && body.channel !== 'legacy') {
        writeJSON(res, 400, { error: 'channel must be encrypted or legacy' });
        return;
      }
      const requestedChannel = body.channel as 'encrypted' | 'legacy' | undefined;
      const identity = await config.nodeRegistry.verifySettings(nodeMatch[1], body.token, requestedChannel);
      if (!identity) {
        writeJSON(res, 422, { error: 'Node did not verify the new token' });
        return;
      }
      if (!await config.nodeRegistry.activateNode(nodeMatch[1], body.token, requestedChannel)) {
        writeJSON(res, 409, { error: 'Node settings changed before activation' });
        return;
      }
      writeJSON(res, 200, {
        verified: true,
        site_id: identity.site_id,
        control_channel: requestedChannel ?? (await config.nodeRegistry.getNode(nodeMatch[1]))?.channel ?? 'legacy',
        capabilities: identity.capabilities,
      });
      return;
    }

    // Lifecycle commands: restart and challenge rotation (admin only).
    const commandMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)\/commands\/([^/]+)$/);
    if (commandMatch && method === 'POST') {
      if (!config.nodeRegistry || !config.poller) {
        writeJSON(res, 503, { error: 'Node registry or poller not configured' });
        return;
      }
      if (!canManageHoneypots()) {
        writeJSON(res, 401, { error: 'Unauthorized' });
        return;
      }
      const node = await config.nodeRegistry.getNode(commandMatch[1]);
      if (!node) {
        writeJSON(res, 404, { error: 'Node not found' });
        return;
      }
      const token = await config.nodeRegistry.decryptToken(node.site_id);
      if (!token) {
        writeJSON(res, 401, { error: 'Node credentials unavailable' });
        return;
      }
      const endpoint = {
        host: node.host,
        port: node.port,
        token,
        tls: node.tls ?? 'http',
        channel: node.channel ?? 'legacy',
      };
      const commandId = `${commandMatch[2]}_${Date.now().toString(36)}`;
      const commandName = commandMatch[2];
      const commandType = commandName === 'restart'
        ? 'control.restart'
        : commandName === 'rotate_challenges'
          ? 'control.rotate_challenges'
          : commandName === 'configure_honeypot'
            ? 'control.configure_honeypot'
            : commandName === 'apply_template'
              ? 'control.apply_template'
            : null;
      if (!commandType) {
        writeJSON(res, 404, { error: 'Unknown node command' });
        return;
      }
      let params: Record<string, unknown> = {};
      if (commandType === 'control.configure_honeypot') {
        if (!node.capabilities.includes('control.configure_honeypot')) {
          writeJSON(res, 409, { error: 'Node does not advertise honeypot configuration support' });
          return;
        }
        const raw = await readBody(req);
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          writeJSON(res, 400, { error: 'Invalid JSON' });
          return;
        }
        const body = parsed as { port?: unknown; profile?: unknown };
        if (typeof body.port !== 'number' || !Number.isInteger(body.port) || body.port < 1 || body.port > 65535) {
          writeJSON(res, 400, { error: 'port (1-65535) is required' });
          return;
        }
        if (!isHoneypotProfile(body.profile)) {
          writeJSON(res, 400, { error: 'profile must be one of: all, http, wiki, openapi, mcp' });
          return;
        }
        if (body.port === node.port) {
          writeJSON(res, 400, { error: 'The exposed port must differ from the control API port' });
          return;
        }
        params = { port: body.port, profile: body.profile };
      }
      if (commandType === 'control.apply_template') {
        if (!node.capabilities.includes('control.apply_template')) {
          writeJSON(res, 409, { error: 'Node does not advertise template configuration support' });
          return;
        }
        const raw = await readBody(req);
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw || '{}');
        } catch {
          writeJSON(res, 400, { error: 'Invalid JSON' });
          return;
        }
        const body = parsed as { template_id?: unknown; version?: unknown };
        if (typeof body.template_id !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(body.template_id)) {
          writeJSON(res, 400, { error: 'template_id is required' });
          return;
        }
        const version = body.version === undefined ? undefined : body.version;
        if (version !== undefined && (!Number.isInteger(version) || Number(version) < 1)) {
          writeJSON(res, 400, { error: 'version must be a positive integer' });
          return;
        }
        const template = await storage.getHoneypotTemplate(body.template_id, version as number | undefined);
        if (!template) {
          writeJSON(res, 404, { error: 'Template not found' });
          return;
        }
        params = { template };
      }
      const nodeClient = config.nodeClient;
      if (!nodeClient) {
        writeJSON(res, 503, { error: 'Node client not configured' });
        return;
      }
      const command = await nodeClient.fetchCommand(endpoint, commandId, commandType, params);
      if ('kind' in command) {
        writeJSON(res, 502, { error: command.message });
        return;
      }
      const runtime = command.outcome as { port?: unknown; profile?: unknown; template_id?: unknown; template_version?: unknown };
      if (commandType === 'control.configure_honeypot' && typeof runtime?.port === 'number' && typeof runtime?.profile === 'string') {
        await config.nodeRegistry.updateNodeRuntime(node.site_id, {
          honeypot_port: runtime.port,
          service_profile: runtime.profile,
        });
      }
      if (commandType === 'control.apply_template' && typeof runtime?.template_id === 'string') {
        await config.nodeRegistry.updateNodeRuntime(node.site_id, {
          template_id: runtime.template_id,
          template_version: typeof runtime.template_version === 'number' ? runtime.template_version : null,
          service_profile: typeof runtime.profile === 'string' ? runtime.profile : undefined,
        });
      }
      writeJSON(res, 200, { command_id: commandId, type: commandType, outcome: command });
      return;
    }

    // Console self-defense: unknown paths from one IP = directory busting.
    consoleDefense.recordScanPath(clientIp, path);
    writeJSON(res, 404, { error: 'Not found' });
  });

  // Console self-defense persistence: drain in-memory attacker state into
  // attacker_activity under site_id "central" so the dashboard, /metrics,
  // and the alerting pipeline (Splunk/OpenCTI) see the console's own
  // attackers through the same telemetry as honeypot attackers.
  let defenseTimer: ReturnType<typeof setInterval> | null = null;
  const drainConsoleAttackers = (): void => {
    const now = Date.now();
    const snaps = consoleDefense.snapshot();
    for (const s of snaps) {
      if (s.loginFailures === 0 && s.apiProbeFailures === 0 && s.scannedPaths === 0 && !s.banned) continue;
      const kinds: string[] = [];
      if (s.loginFailures > 0) kinds.push('login_bruteforce');
      if (s.apiProbeFailures > 0) kinds.push('api_probe');
      if (s.scannedPaths > 0) kinds.push('path_scan');
      const id = consoleAttackerId(s.ip, now);
      void storage.saveAttackerActivity({
        id,
        session_id: '',
        site_id: CENTRAL_SITE_ID,
        ts: now,
        event_type: `console.${kinds.join('.') || 'threat'}`,
        ip: s.ip,
        user_agent: '',
        path: '',
        classification: 'console-attacker',
        confidence: CONSOLE_ATTACKER_CONFIDENCE,
        tooling: null,
        level_max: consoleAttackerLevel(s.banned),
        flags_fired: null,
        win_isolated: false,
        meta_detect: false,
        capability: null,
        intent: null,
        severity: consoleAttackerSeverity(s.banned),
        payload_json: JSON.stringify({ kinds, loginFailures: s.loginFailures, apiProbeFailures: s.apiProbeFailures, scannedPaths: s.scannedPaths, offenses: s.offenseCount, banned: s.banned }),
      }).catch(() => undefined);
    }
  };

  return {
    server,
    listen: () => new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, async () => {
        const idp = oidcConfig ? `OIDC issuer ${oidcConfig.issuer}` : 'legacy token login (no OIDC issuer configured)';
        console.log(`Central control plane listening on ${config.host}:${config.port} — auth: ${idp}`);
        if (oidcConfig) console.log('  Keycloak realm "vaivar", client "vaivar-central"; groups: vaivar-viewer/user/admin/superadmin');
        if (!devMode) defenseTimer = setInterval(drainConsoleAttackers, CONSOLE_DEFENSE_DRAIN_INTERVAL_MS);
        resolve();
      });
    }),
    close: () => new Promise<void>((resolve) => {
      if (defenseTimer) { clearInterval(defenseTimer); defenseTimer = null; }
      drainConsoleAttackers();
      server.close(() => resolve());
    }),
  };
};
