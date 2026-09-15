/**
 * vAIvar HTTP/S Server
 * JSON API, health, and metrics (one internal plane).
 *
 * One private listener for dashboard, API, metrics and MCP diagnostics.
 * The attacker surface uses a separate public listener.
 */

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { SessionEngine } from '../engine/session';
import type { StorageIndexer } from '../storage/indexer';
import type { NodeIdentity } from '../node/identity';
import { createBarrierAuth, bearerToken, cookieToken } from './auth';
import { renderDashboardHTML } from './dashboard';
import { readVaivarLogoSvg, VAIVAR_LOGO_URL } from '../branding';
import {
  CONTROL_CHANNEL_MAX_PLAINTEXT_BYTES,
  controlEnvelopeReplayKey,
  deriveControlKey,
  openControlMessage,
  sealControlMessage,
  type ControlRequest,
  type ControlResponse,
} from '../security/control-channel';

export interface HTTPServerConfig {
  readonly port: number;
  readonly host: string;
  readonly engine: SessionEngine;
  readonly storage: StorageIndexer;
  readonly ctiEnabled: boolean;
  readonly barrierToken?: string;
  /** Application-level encryption for Central ↔ node traffic. The socket is
   * deliberately plain HTTP so a target host needs no TLS installation. */
  readonly controlCrypto?: { apiToken: string };
  readonly mcpHandler?: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  /** Triggered after a restart command is accepted and the response is sent.
   *  The node flushes events, closes cleanly, and exits so the supervisor
   *  (e.g. Docker) restarts it. Not invoked for idempotent re-submissions. */
  readonly onRestart?: () => Promise<void>;
  /** Called when a rotate_challenges command succeeds. Receives the new
   *  generation number so the engine can re-derive seeds for new sessions. */
  readonly onRotateChallenges?: (newGeneration: number) => void;
  /** Apply a validated public port/profile update from Central. */
  readonly onConfigureHoneypot?: (params: Record<string, unknown>) => Promise<unknown>;
  /** Apply a validated declarative public template from Central. */
  readonly onApplyHoneypotTemplate?: (params: Record<string, unknown>) => Promise<unknown>;
  /** Node identity resolved at bootstrap (site_id, boot_id, stream_id). May be
   * a promise if storage is not yet initialized when the server is constructed. */
  readonly getNodeIdentity?: () => NodeIdentity | null;
}

export const createHTTPServer = (config: HTTPServerConfig) => {
  const { engine, storage } = config;
  const auth = createBarrierAuth(config.barrierToken);
  const controlKey = config.controlCrypto ? deriveControlKey(config.controlCrypto.apiToken) : null;
  const seenControlMessages = new Map<string, number>();
  let requestCount = 0;
  let errorCount = 0;

  function writeJSONResponse(res: ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(JSON.stringify(body));
  }

  const generateSessionId = (): string => {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return `s_${hex}`;
  };

  const clientIp = (req: IncomingMessage): string | null => {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd.length > 0) return fwd.split(',')[0].trim();
    return req.socket.remoteAddress ?? null;
  };

  interface InternalRequestContext {
    readonly url: string;
    readonly method: string;
    readonly body?: string;
    readonly secure: boolean;
  }

  let requestHandler: (req: IncomingMessage, res: ServerResponse, internal?: InternalRequestContext) => Promise<void>;

  const secureRouteMethods: Record<string, 'GET' | 'POST'> = {
    '/api/node/info': 'GET',
    '/api/events': 'GET',
    '/api/commands': 'POST',
    '/api/control/restart': 'POST',
    '/api/control/rotate_challenges': 'POST',
  };

  const captureResponse = (): { response: ServerResponse; result: ControlResponse } => {
    const result = { status: 500, body: JSON.stringify({ error: 'Empty control response' }) };
    const captureState = { headersSent: false };
    const capture = {
      get headersSent() { return captureState.headersSent; },
      writeHead(status: number) {
        result.status = status;
        captureState.headersSent = true;
        return capture;
      },
      end(body?: unknown) {
        if (body !== undefined) result.body = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);
        captureState.headersSent = true;
        return capture;
      },
    } as unknown as ServerResponse;
    return { response: capture, result };
  };

  const handleSecureRpc = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (!controlKey) {
      writeJSONResponse(res, 404, { error: 'Encrypted control channel is not enabled' });
      return;
    }
    try {
      const raw = await readBody(req);
      const envelope = JSON.parse(raw) as unknown;
      const opened = openControlMessage<ControlRequest>(controlKey, 'request', envelope);
      const now = Date.now();
      for (const [key, seenAt] of seenControlMessages) {
        if (now - seenAt > 10 * 60 * 1000) seenControlMessages.delete(key);
      }
      const replayKey = controlEnvelopeReplayKey(opened.requestId, opened.nonce);
      if (seenControlMessages.has(replayKey)) throw new Error('Replayed control-channel message');
      seenControlMessages.set(replayKey, now);

      const controlRequest = opened.payload;
      if (!controlRequest || typeof controlRequest !== 'object' ||
        (controlRequest.method !== 'GET' && controlRequest.method !== 'POST') ||
        typeof controlRequest.url !== 'string' || !controlRequest.url.startsWith('/') ||
        controlRequest.url.startsWith('//') || controlRequest.url.includes('#') ||
        (controlRequest.body !== undefined && typeof controlRequest.body !== 'string')) {
        throw new Error('Invalid encrypted control request');
      }
      const target = new URL(controlRequest.url, 'http://vaivar.invalid');
      const targetPath = target.pathname.replace(/\/+$/, '') || '/';
      if (target.origin !== 'http://vaivar.invalid' ||
        secureRouteMethods[targetPath] !== controlRequest.method ||
        (controlRequest.body !== undefined && Buffer.byteLength(controlRequest.body, 'utf8') > CONTROL_CHANNEL_MAX_PLAINTEXT_BYTES)) {
        throw new Error('Control route is not permitted');
      }
      const normalizedUrl = `${targetPath}${target.search}`;
      const captured = captureResponse();
      await requestHandler(req, captured.response, {
        url: normalizedUrl,
        method: controlRequest.method,
        body: controlRequest.body,
        secure: true,
      });
      const responseEnvelope = sealControlMessage(controlKey, 'response', opened.requestId, captured.result);
      writeJSONResponse(res, 200, responseEnvelope);
    } catch {
      // Do not echo parsing/decryption details. In particular, a caller that
      // does not know the token must not learn whether a route exists.
      writeJSONResponse(res, 400, { error: 'Invalid encrypted control request' });
    }
  };

  requestHandler = async (req: IncomingMessage, res: ServerResponse, internal?: InternalRequestContext) => {
    const url = internal?.url ?? req.url ?? '/';
    const method = internal?.method ?? req.method ?? 'GET';
    const requestedPath = url.split('?')[0].replace(/\/+$/, '') || '/';
    const aliases: Record<string, string> = {
      '/api/dashboard': '/api/v1/dashboard',
      '/api/prometheus': '/metrics',
      '/api/metrics': '/metrics',
      '/api/metrics/realtimeattacks': '/api/v1/activity',
    };
    const path = aliases[requestedPath] ?? requestedPath;
    const ip = clientIp(req);
    const userAgent = req.headers['user-agent'] ?? '';
    const src = { ip, userAgent };

    requestCount += 1;

    // Branding is a public UI asset, so it must remain available before the
    // private-plane authentication and encrypted-channel checks below.
    if (path === VAIVAR_LOGO_URL && method === 'GET') {
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
      res.end(logo);
      return;
    }

    if (!internal?.secure && path === '/api/secure/rpc' && method === 'POST') {
      await handleSecureRpc(req, res);
      return;
    }

    // In an encrypted deployment, private routes never accept a plaintext
    // bearer token. This prevents an operator or future integration from
    // accidentally putting the shared secret on the wire. The health probe is
    // intentionally minimal and remains open for Docker.
    if (!internal?.secure && config.controlCrypto && path !== '/health') {
      writeJSONResponse(res, 426, { error: 'Encrypted control channel required' });
      errorCount += 1;
      return;
    }

    // Legacy/unit-test mode: non-health requests require the barrier token.
    if (!internal?.secure && path !== '/health' && !auth.verify(bearerToken(req)) && !auth.verifyCookie(cookieToken(req))) {
      writeJSONResponse(res, 401, { error: 'Unauthorized' });
      errorCount += 1;
      return;
    }

    try {
      if ((path === '/' || path === '/dashboard') && method === 'GET') {
        auth.setCookie(res);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(renderDashboardHTML(config.port, config.port));
        return;
      }

      if (path === '/api/v1/dashboard' && method === 'GET') {
        const stats = await storage.getStats();
        writeJSONResponse(res, 200, { overview: stats, uptime: process.uptime(), live_sessions: engine.sessionCount });
        return;
      }

      // The existing MCP skin is available for authenticated diagnostics on
      // the same port. It is not an administrative command interface.
      if ((path === '/api/mcp' || path === '/mcp') && config.mcpHandler) {
        if (method !== 'POST') {
          writeJSONResponse(res, 405, { error: 'Method Not Allowed' });
          return;
        }
        await config.mcpHandler(req, res);
        return;
      }

      // Health check endpoint (internal)
      if (path === '/health' && method === 'GET') {
        writeJSONResponse(res, 200, {
          status: 'ok',
          uptime: process.uptime(),
          control_port: config.port,
          honeypot_port: config.getNodeIdentity?.()?.honeypot_port ?? null,
        });
        return;
      }

      // Node identity (operator plane): requires the barrier token, never
      // reveals secrets. Central uses this to verify identity before enrolling.
      if (path === '/api/node/info' && method === 'GET') {
        const identity = config.getNodeIdentity?.();
        if (!identity) {
          writeJSONResponse(res, 503, { error: 'Node identity not initialized' });
          return;
        }
        // Read the live challenge generation from storage — it may have
        // been incremented since bootstrap cached the identity.
        const generation = await storage.getChallengeGeneration();
        writeJSONResponse(res, 200, {
          ...identity,
          challenge_generation: generation,
        });
        return;
      }

      // Durable event feed: cursor-paginated, idempotent. Central polls
      // this endpoint to pull new events without re-fetching old ones.
      if (path === '/api/events' && method === 'GET') {
        const params = new URLSearchParams(url.split('?')[1] ?? '');
        const siteId = params.get('site_id') ?? '';
        const streamId = params.get('stream_id') ?? '';
        const cursor = params.get('after') ?? null;
        const limit = Math.min(Math.max(parseInt(params.get('limit') ?? '500', 10) || 500, 1), 1000);
        const identity = config.getNodeIdentity?.();
        if (identity && siteId && siteId !== identity.site_id) {
          writeJSONResponse(res, 403, { error: 'site_id does not match this node' });
          return;
        }
        if (identity && streamId && streamId !== identity.stream_id) {
          writeJSONResponse(res, 403, { error: 'stream_id does not match this node' });
          return;
        }
        const result = await storage.getEventPage(identity?.site_id ?? siteId, cursor, limit);
        writeJSONResponse(res, 200, {
          spec: 'vaivar.sync.v1',
          site_id: identity?.site_id ?? siteId,
          stream_id: identity?.stream_id ?? streamId,
          events: result.events,
          next_cursor: result.next_cursor,
          high_watermark: result.high_watermark,
          has_more: result.has_more,
        });
        return;
      }

      // Control plane: idempotent command execution. Central POSTs a
      // command here; the node executes it once and records the outcome
      // in the audit journal.
      if (path === '/api/commands' && method === 'POST') {
        const raw = internal?.body !== undefined ? internal.body : await readBody(req);
        let parsed: { command_id?: string; type?: string; params?: Record<string, unknown> } = {};
        try {
          parsed = JSON.parse(raw);
        } catch {
          writeJSONResponse(res, 400, { error: 'Invalid JSON' });
          return;
        }
        if (!parsed.command_id || typeof parsed.type !== 'string') {
          writeJSONResponse(res, 400, { error: 'command_id and type are required' });
          return;
        }
        const params = parsed.params ?? {};
        if (parsed.type === 'control.configure_honeypot' && !config.onConfigureHoneypot) {
          writeJSONResponse(res, 503, { error: 'Honeypot configuration is not available' });
          return;
        }
        if (parsed.type === 'control.apply_template' && !config.onApplyHoneypotTemplate) {
          writeJSONResponse(res, 503, { error: 'Honeypot template configuration is not available' });
          return;
        }
        const outcome = await storage.executeCommand(
          parsed.command_id,
          parsed.type,
          params,
          parsed.type === 'control.configure_honeypot'
            ? () => config.onConfigureHoneypot!(params)
            : parsed.type === 'control.apply_template'
              ? () => config.onApplyHoneypotTemplate!(params)
            : undefined
        );
        writeJSONResponse(res, 200, {
          command_id: parsed.command_id,
          type: parsed.type,
          executed: outcome.executed,
          outcome: outcome.outcome,
        });
        return;
      }

       // Control plane: lifecycle operations. Requires the node to advertise
       // the corresponding capability in /api/node/info.
       if (path === '/api/control/restart' && method === 'POST') {
         const raw = internal?.body !== undefined ? internal.body : await readBody(req);
         let parsed: { command_id?: string } = {};
         try {
           parsed = JSON.parse(raw);
         } catch {
           writeJSONResponse(res, 400, { error: 'Invalid JSON' });
           return;
         }
         const commandId = parsed.command_id ?? `restart_${Date.now().toString(36)}`;
         const outcome = await storage.executeCommand(commandId, 'control.restart', {});
         writeJSONResponse(res, 200, {
           command_id: commandId,
           type: 'control.restart',
           executed: outcome.executed,
           outcome: outcome.outcome,
         });
         // After the response is sent, trigger a graceful restart. Only
         // fires when the command genuinely executed (idempotency guard).
         if (outcome.executed && config.onRestart) {
           setImmediate(() => {
             void (config.onRestart?.() ?? Promise.resolve());
           });
         }
         return;
       }

       if (path === '/api/control/rotate_challenges' && method === 'POST') {
         const raw = internal?.body !== undefined ? internal.body : await readBody(req);
         let parsed: { command_id?: string } = {};
         try {
           parsed = JSON.parse(raw);
         } catch {
           writeJSONResponse(res, 400, { error: 'Invalid JSON' });
           return;
         }
         const commandId = parsed.command_id ?? `rotate_${Date.now().toString(36)}`;
         const outcome = await storage.executeCommand(commandId, 'control.rotate_challenges', {});
         if (outcome.executed) {
           const newGen = (await storage.getChallengeGeneration()) + 1;
           await storage.setChallengeGeneration(newGen);
           config.onRotateChallenges?.(newGen);
         }
         writeJSONResponse(res, 200, {
           command_id: commandId,
           type: 'control.rotate_challenges',
           executed: outcome.executed,
           outcome: outcome.outcome,
           challenge_generation: await storage.getChallengeGeneration(),
         });
         return;
       }

      // Prometheus-compatible metrics endpoint (internal)
      if (path === '/metrics' && method === 'GET') {
        const stats = await storage.getStats();
        const uptime = process.uptime();

        const output = [
          '# HELP vaivar_sessions_total Total number of recorded sessions',
          '# TYPE vaivar_sessions_total gauge',
          `vaivar_sessions_total ${stats.sessions}`,
          '',
          '# HELP vaivar_events_total Total number of events logged',
          '# TYPE vaivar_events_total gauge',
          `vaivar_events_total ${stats.events}`,
          '',
          '# HELP vaivar_flags_total Total number of flags triggered',
          '# TYPE vaivar_flags_total gauge',
          `vaivar_flags_total ${stats.flags}`,
          '',
          '# HELP vaivar_storage_bytes Current storage size in bytes',
          '# TYPE vaivar_storage_bytes gauge',
          `vaivar_storage_bytes ${stats.size_bytes}`,
          '',
          '# HELP vaivar_uptime_seconds Service uptime in seconds',
          '# TYPE vaivar_uptime_seconds gauge',
          `vaivar_uptime_seconds ${uptime.toFixed(2)}`,
          '',
          '# HELP vaivar_requests_total Total HTTP requests processed',
          '# TYPE vaivar_requests_total counter',
          `vaivar_requests_total ${requestCount}`,
          '',
          '# HELP vaivar_errors_total Total HTTP errors encountered',
          '# TYPE vaivar_errors_total counter',
          `vaivar_errors_total ${errorCount}`,
          '',
          '# HELP vaivar_memory_heap_used_bytes Heap memory used by process',
          '# TYPE vaivar_memory_heap_used_bytes gauge',
          `vaivar_memory_heap_used_bytes ${process.memoryUsage().heapUsed}`,
          '',
          '# HELP vaivar_cti_enabled Whether the OpenCTI connector is enabled',
          '# TYPE vaivar_cti_enabled gauge',
          `vaivar_cti_enabled ${config.ctiEnabled ? 1 : 0}`,
        ].join('\n');

        res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
        res.end(output);
        return;
      }

      // Session creation (attacker plane)
      if (path === '/api/v1/session' && method === 'POST') {
        const sessionId = generateSessionId();
        engine.getOrCreate(sessionId, src);
        writeJSONResponse(res, 201, { sessionId, status: 'created' });
        return;
      }

      // Get session
      const sessionMatch = path.match(/^\/api\/v1\/session\/([^/]+)$/);
      if (sessionMatch && method === 'GET') {
        const sessionId = sessionMatch[1];
        const snapshot = engine.snapshot(sessionId);
        if (!snapshot) {
          errorCount++;
          writeJSONResponse(res, 404, { error: 'Session not found' });
          return;
        }
        writeJSONResponse(res, 200, {
          sessionId: snapshot.sessionId,
          createdAt: snapshot.createdAt,
          lastSeenAt: snapshot.lastSeenAt,
          budget: snapshot.budget,
          levelMax: snapshot.levelMax,
          flagsFired: engine.peekEvents(sessionId).filter((e) => e.type === 'flag.hit').length,
        });
        return;
      }

      // Get node (operator plane: full metadata, no seed leak)
      const nodeMatch = path.match(/^\/api\/v1\/node\/([^/]+)(?:\/(.*))?$/);
      if (nodeMatch && method === 'GET') {
        const sessionId = nodeMatch[1];
        const nodePath = nodeMatch[2] ? `/${nodeMatch[2]}` : '/';
        const result = engine.serveNode(sessionId, src, nodePath);
        if (!result.ok) {
          errorCount++;
          writeJSONResponse(res, 404, { error: 'Node not found' });
          return;
        }
        const { node } = result.value;
        engine.recordRequest(sessionId, src, node.metadata.size);
        engine.observeMetaProbe(sessionId, nodePath);
        writeJSONResponse(res, 200, {
          sessionId,
          node,
        });
        return;
      }

      // Flag submission (operator plane)
      if (path === '/api/v1/flag' && method === 'POST') {
        const body = internal?.body !== undefined ? internal.body : await readBody(req);
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
          levelMax: result.levelMax,
        });
        return;
      }

      // List sessions (operator plane; no seed)
      if (path === '/api/v1/sessions' && method === 'GET') {
        const sessions = engine.listSessions().map((s) => ({
          sessionId: s.sessionId,
          createdAt: s.createdAt,
          lastSeenAt: s.lastSeenAt,
          levelMax: s.levelMax,
          winIsolated: s.winIsolated,
          metaDetect: s.metaDetect,
          flagsFired: engine.peekEvents(s.sessionId).filter((e) => e.type === 'flag.hit').length,
          dwellSeconds: s.intent.dwellSeconds,
        }));
        writeJSONResponse(res, 200, { sessions });
        return;
      }

      // Transversal event log: unified v2 projection for a session
      const envelopeMatch = path.match(/^\/api\/v1\/events\/([^/]+)$/);
      if (envelopeMatch && method === 'GET') {
        const limit = parseInt(String(url.split('?')[1]?.match(/limit=(\d+)/)?.[1] ?? '100'), 10);
        const envelopes = await storage.getEventEnvelopes(envelopeMatch[1], Math.min(limit, 500));
        writeJSONResponse(res, 200, {
          session_id: envelopeMatch[1],
          count: envelopes.length,
          schema_version: 2,
          events: envelopes,
        });
        return;
      }

      // Attacker activity log: operator-only projection, no secrets
      const activityMatch = path.match(/^\/api\/v1\/activity\/?([^/]*)?$/);
      if (activityMatch && method === 'GET') {
        const sessionId = activityMatch[1] && activityMatch[1].length > 0 ? activityMatch[1] : null;
        const limit = parseInt(String(url.split('?')[1]?.match(/limit=(\d+)/)?.[1] ?? '100'), 10);
        const activity = await storage.listAttackerActivity(sessionId, Math.min(limit, 500));
        writeJSONResponse(res, 200, {
          session_id: sessionId,
          count: activity.length,
          activity,
        });
        return;
      }

      // 404
      errorCount++;
      writeJSONResponse(res, 404, { error: 'Not found' });
    } catch (err) {
      errorCount++;
      console.error('HTTP Request error:', err);
      if (!res.headersSent) {
        writeJSONResponse(res, 500, { error: 'Internal Server Error' });
      }
    }
  };

  const server = createHttpServer(requestHandler);

  return {
    server,
    listen: () => new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, () => {
        console.log(`HTTP server listening on ${config.host}:${config.port}${config.controlCrypto ? ' (encrypted control channel)' : ''}`);
        resolve();
      });
    }),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
};

const readBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => resolve(body));
    req.on('error', () => resolve(body));
  });
