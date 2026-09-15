/**
 * vAIvar Honeypot Server
 * Exposed server for attackers - only serves honeypot endpoints
 * No dashboard, health, or metrics exposed. No seed leak: the session seed
 * NEVER leaves the server; attackers only see generated world content.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import type { SessionEngine } from '../engine/session';
import { createOpenAPISkin } from '../skins/openapi';
import { toPublicNode } from '../graph/generator';
import { sanitizeBrandStrings } from '../skins/validators';
import { DEFAULT_HONEYPOT_PROFILE, isHoneypotProfile, normalizeHoneypotProfile, type HoneypotProfile } from '../node/config';
import { createDefaultTemplate } from '../templates/defaults';
import { renderTemplatePage, templateHasPage } from '../templates/render';
import { templateAppliesToProfile, validateHoneypotTemplate, type HoneypotTemplate } from '../templates/types';

export interface HoneypotServerConfig {
  readonly port: number;
  /** Control API port; the public port must remain separate from it. */
  readonly controlPort?: number;
  readonly host: string;
  readonly engine: SessionEngine;
  readonly mcpHandler?: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  readonly wikiTitle?: string;
  readonly openAPITitle?: string;
  readonly openAPIVersion?: string;
  readonly openAPIBasePath?: string;
  readonly profile?: HoneypotProfile;
  readonly template?: HoneypotTemplate;
}

export interface HoneypotServerUpdate {
  readonly port?: number;
  readonly profile?: HoneypotProfile;
  readonly template?: HoneypotTemplate;
}

const MAX_BODY = 64 * 1024;

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 600; // per IP per minute

interface RateBucket {
  timestamps: number[];
}

export const createHoneypotServer = (config: HoneypotServerConfig) => {
  const { engine } = config;
  const rateBuckets: Map<string, RateBucket> = new Map();
  let requestCount = 0;
  let activePort = config.port;
  let activeProfile = normalizeHoneypotProfile(config.profile ?? DEFAULT_HONEYPOT_PROFILE);
  const initialTemplate = config.template ?? createDefaultTemplate(activeProfile);
  const initialTemplateCheck = validateHoneypotTemplate(initialTemplate);
  if (!initialTemplateCheck.ok) throw new Error(initialTemplateCheck.error);
  let activeTemplate = initialTemplateCheck.template;
  if (!templateAppliesToProfile(activeTemplate, activeProfile)) {
    activeTemplate = createDefaultTemplate(activeProfile);
  }
  let listening = false;

  const validateUpdate = (update: HoneypotServerUpdate): { port: number; profile: HoneypotProfile; template: HoneypotTemplate } => {
    const port = update.port ?? activePort;
    const profileChanged = update.profile !== undefined && update.profile !== activeProfile;
    const profile = normalizeHoneypotProfile(update.profile ?? activeProfile);
    let template = update.template ?? activeTemplate;
    if (update.template !== undefined) {
      const checked = validateHoneypotTemplate(update.template);
      if (!checked.ok) throw new Error(checked.error);
      template = checked.template;
    } else if (profileChanged && !templateAppliesToProfile(template, profile)) {
      template = createDefaultTemplate(profile);
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('honeypot port must be an integer between 1 and 65535');
    }
    if (config.controlPort !== undefined && port === config.controlPort) {
      throw new Error('honeypot port must differ from the control API port');
    }
    if (update.profile !== undefined && !isHoneypotProfile(update.profile)) {
      throw new Error('unsupported honeypot service profile');
    }
    if (!templateAppliesToProfile(template, profile)) {
      throw new Error('template profile does not match the active honeypot profile');
    }
    return { port, profile, template };
  };

  const clientIp = (req: IncomingMessage): string | null => {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd.length > 0) return fwd.split(',')[0].trim();
    return req.socket.remoteAddress ?? null;
  };

  const isRateLimited = (ip: string): boolean => {
    const now = Date.now();
    const bucket = rateBuckets.get(ip) ?? { timestamps: [] };
    bucket.timestamps = bucket.timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (bucket.timestamps.length >= RATE_LIMIT_MAX) {
      rateBuckets.set(ip, bucket);
      return true;
    }
    bucket.timestamps.push(now);
    rateBuckets.set(ip, bucket);
    return false;
  };

  function writeJSONResponse(res: ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(sanitizeBrandStrings(JSON.stringify(body)));
  }

  const readBody = (req: IncomingMessage): Promise<string> =>
    new Promise((resolve) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
        if (body.length > MAX_BODY) {
          body = body.slice(0, MAX_BODY);
          req.destroy();
          resolve(body);
        }
      });
      req.on('end', () => resolve(body));
      req.on('error', () => resolve(body));
    });

  const generateSessionId = (): string => {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return `s_${hex}`;
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = req.url || '/';
    const method = req.method || 'GET';
    const path = url.split('?')[0];
    const ip = clientIp(req);
    const userAgent = req.headers['user-agent'] ?? '';
    let sessionId: string | undefined;

    requestCount += 1;

    if (ip && isRateLimited(ip)) {
      // Throttled: plain 429, no internals.
      writeJSONResponse(res, 429, { error: 'Too many requests' });
      return;
    }

    const src = { ip, userAgent };

    const surfaceEnabled = (surface: HoneypotProfile): boolean =>
      activeProfile === 'all' || activeProfile === surface;

    // Serve operator-provided declarative pages before the built-in skins.
    // Page content is escaped by renderTemplatePage and never executes code.
    if (method === 'GET' && templateAppliesToProfile(activeTemplate, activeProfile) && templateHasPage(activeTemplate, path)) {
      const templateSession = engine.getOrCreate(`template-${path}`, src);
      const rendered = renderTemplatePage(activeTemplate, path, templateSession.seed);
      if (rendered) {
        res.writeHead(rendered.status, rendered.headers);
        res.end(rendered.body);
        return;
      }
    }

    // Keep the MCP deception skin on the public port, without opening a
    // separate control-plane socket.
    if (surfaceEnabled('mcp') && path === '/mcp' && method === 'POST' && config.mcpHandler) {
      await config.mcpHandler(req, res);
      return;
    }

    // Session creation: NO seed in response.
    if (surfaceEnabled('http') && path === '/api/v1/session' && method === 'POST') {
      sessionId = generateSessionId();
      engine.getOrCreate(sessionId, src);
      writeJSONResponse(res, 201, { sessionId, status: 'created' });
      return;
    }

    // Get node: public projection only (no isTrap/isSecret/level metadata).
    const nodeMatch = path.match(/^\/api\/v1\/node\/([^/]+)(?:\/(.*))?$/);
    if (surfaceEnabled('http') && nodeMatch && method === 'GET') {
      const sessionId = nodeMatch[1];
      const nodePath = nodeMatch[2] ? `/${nodeMatch[2]}` : '/';
      const result = engine.serveNode(sessionId, src, nodePath);
      if (!result.ok) {
        writeJSONResponse(res, 404, { error: 'Not found' });
        return;
      }
      const { node } = result.value;
      engine.recordRequest(sessionId, src, node.metadata.size);
      engine.observeMetaProbe(sessionId, nodePath);
      writeJSONResponse(res, 200, toPublicNode(node, engine.snapshot(sessionId)?.levelMax ?? 0));
      return;
    }

    // OpenAPI skin: deterministic API docs per session.
    if (surfaceEnabled('openapi') && (path === '/openapi.json' || path === '/openapi.yaml')) {
      const s = engine.getOrCreate(sessionId || 'openapi-fallback', src);
      const seed = s.seed;
      const doc = createOpenAPISkin({
        title: config.openAPITitle ?? 'API',
        version: config.openAPIVersion ?? '1.0',
        basePath: config.openAPIBasePath ?? '/v1',
        seed,
      });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(JSON.stringify(doc));
      return;
    }

    // Flag submission: generic response shape for all rejections.
    if (surfaceEnabled('http') && path === '/api/v1/flag' && method === 'POST') {
      const body = await readBody(req);
      let parsed: { sessionId?: string; code?: string; nodeId?: string } = {};
      try {
        parsed = JSON.parse(body);
      } catch {
        writeJSONResponse(res, 400, { error: 'Invalid JSON' });
        return;
      }
      if (!parsed.sessionId || typeof parsed.code !== 'string') {
        writeJSONResponse(res, 400, { error: 'sessionId and code required' });
        return;
      }
      const result = engine.submitCode(
        parsed.sessionId,
        src,
        parsed.code,
        'http',
        parsed.nodeId ?? 'unknown'
      );
      writeJSONResponse(res, 200, {
        accepted: result.accepted,
        meta: result.meta,
      });
      return;
    }

    // All other paths return 404 to hide internal structure.
    writeJSONResponse(res, 404, { error: 'Not found' });
  });

  const listen = (): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(activePort, config.host, () => {
        listening = true;
        console.log(`Honeypot server listening on ${config.host}:${activePort}`);
        resolve();
      });
    });

  const close = (): Promise<void> =>
    new Promise<void>((resolve) => {
      if (!listening) {
        resolve();
        return;
      }
      server.close(() => {
        listening = false;
        resolve();
      });
    });

  return {
    server,
    requestCount: () => requestCount,
    get port() { return activePort; },
    get profile() { return activeProfile; },
    listen,
    close,
    get template() { return activeTemplate; },
    configure: async (update: HoneypotServerUpdate): Promise<{ port: number; profile: HoneypotProfile; template: HoneypotTemplate }> => {
      const next = validateUpdate(update);
      if (next.port === activePort && next.profile === activeProfile && JSON.stringify(next.template) === JSON.stringify(activeTemplate)) return next;
      const previousPort = activePort;
      const previousProfile = activeProfile;
      const previousTemplate = activeTemplate;
      if (listening && next.port !== activePort) {
        await close();
        activePort = next.port;
        activeProfile = next.profile;
        activeTemplate = next.template;
        try {
          await listen();
        } catch (error) {
          // Try to restore the previous listener if the requested port is
          // unavailable. The caller can report the failure without leaving
          // the honeypot offline.
          activePort = previousPort;
          activeProfile = previousProfile;
          activeTemplate = previousTemplate;
          try { await listen(); } catch { /* best effort */ }
          throw error;
        }
      } else {
        activePort = next.port;
        activeProfile = next.profile;
        activeTemplate = next.template;
      }
      return next;
    },
  };
};
