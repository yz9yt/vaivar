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

import { ok, err, type Result } from '../fp/core';
import type { BudgetLimits } from '../types/common';
import { DEFAULT_BUDGET } from '../types/common';
import type { Event } from '../types/events';
import { createHTTPServer } from '../server/http';
import { createHoneypotServer } from '../server/honeypot';
import { createMCPHandler } from '../mcp/server';
import { SessionEngine } from '../engine/session';
import { EventBus } from '../events/bus';
import { StorageIndexer, createStorage } from '../storage/indexer';
import { createRemoteEventSink } from '../central/forwarder';
import { AppLogger } from '../logging/applog';
import { createEventLogSink, createAttackerActivitySink } from '../logging/sinks';
import type { NodeIdentity } from '../node/identity';
import { NODE_CAPABILITIES } from '../node/identity';
import { DEFAULT_HONEYPOT_PROFILE, isHoneypotProfile, normalizeHoneypotProfile, type HoneypotProfile } from '../node/config';
import { createDefaultTemplate } from '../templates/defaults';
import { validateHoneypotTemplate, type HoneypotTemplate } from '../templates/types';
import fs from 'fs';
import path from 'path';

/**
 * Resolve the SQLite database path. Accepts either a directory (common in
 * container deployments via DATA_PATH) or a full file path; a directory
 * gets a `vaivar.db` file inside it.
 */
const resolveDbPath = (raw: string): string => {
  if (raw === ':memory:' || raw.endsWith('.db') || raw.endsWith('.sqlite')) return raw;
  try {
    if (fs.existsSync(raw) && fs.statSync(raw).isDirectory()) {
      return path.join(raw, 'vaivar.db');
    }
  } catch {
    // Fall through: treat as file path.
  }
  return raw;
};

export interface BootstrapConfig {
  readonly masterSecret: string;
  readonly budget?: BudgetLimits;
  readonly skins: readonly string[];
  readonly ports?: { http: number; honeypot: number };
  /** Application-level encryption for Central ↔ node control traffic. The
   * socket remains plain HTTP; the shared API token is never sent on it. */
  readonly controlCrypto?: { apiToken: string };
  /** Public service profile: all, http, wiki, openapi or mcp. */
  readonly honeypotProfile?: HoneypotProfile;
  /** Optional declarative public template to install at startup. */
  readonly honeypotTemplate?: HoneypotTemplate;
  readonly dbPath?: string;
  readonly logPath?: string;
  readonly flushIntervalMs?: number;
  readonly apiToken?: string;
  /** Optional lifecycle hooks. If omitted, the default behavior is to
   * call `process.exit(42)` for restart and `process.exit(0)` after
   * rotation so supervisors can relaunch the container. Tests or
   * supervisors should provide their own hooks instead. */
  readonly onRestart?: () => Promise<void>;
  readonly onRotateChallenges?: (newGeneration: number) => void;
  /** Multi-sede: when set, forward every engine event to the central plane. */
  readonly central?: {
    readonly url: string;
    readonly ingestToken: string;
    readonly siteId: string;
  };
}

export interface VaivarApp {
  readonly engine: SessionEngine;
  readonly bus: EventBus;
  readonly storage: StorageIndexer;
  readonly appLogger: AppLogger;
  readonly nodeIdentity: NodeIdentity;
  start: () => Promise<{
    http?: { status: string; port: number };
    honeypot: { status: string; port: number };
  }>;
  stop: () => Promise<void>;
  flush: () => Promise<void>;
}

export const bootstrap = async (config: BootstrapConfig): Promise<Result<VaivarApp, Error>> => {
  if (!config.masterSecret || config.masterSecret.length < 32) {
    return err(new Error('Master secret must be at least 32 characters'));
  }

  const budget = config.budget || DEFAULT_BUDGET;

  const requiredPort = (name: string, value?: number): number => {
    const raw = value ?? process.env[name];
    if (!raw) {
      throw new Error(`Missing required port env var ${name}. Set it in your deployment YAML.`);
    }
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
      throw new Error(`Invalid port for ${name}: ${raw}`);
    }
    return parsed;
  };

  const httpPort = requiredPort('VAIVAR_PORT_HTTP', config.ports?.http);
  const honeypotPort = requiredPort('VAIVAR_PORT_HONEYPOT', config.ports?.honeypot);
  if (httpPort === honeypotPort) return err(new Error('Public and private API ports must be different'));
  const profileInput = config.honeypotProfile ?? process.env.VAIVAR_HONEYPOT_PROFILE ?? DEFAULT_HONEYPOT_PROFILE;
  if (!isHoneypotProfile(profileInput)) {
    return err(new Error('VAIVAR_HONEYPOT_PROFILE must be one of: all, http, wiki, openapi, mcp'));
  }
  const initialHoneypotProfile = normalizeHoneypotProfile(profileInput);
  const apiToken = config.apiToken ?? process.env.VAIVAR_API_TOKEN ?? '';
  if (apiToken.trim().length < 16) return err(new Error('VAIVAR_API_TOKEN must contain at least 16 characters'));
  if (config.controlCrypto && config.controlCrypto.apiToken !== apiToken) {
    return err(new Error('controlCrypto.apiToken must match VAIVAR_API_TOKEN'));
  }

  // The legacy ingest-token forwarder is opt-in only. It must never be
  // required: the node boots without a central URL, and central initiates
  // authenticated connections here.
  const central = config.central ?? (
    process.env.VAIVAR_CENTRAL_URL &&
    process.env.VAIVAR_CENTRAL_INGEST_TOKEN &&
    process.env.VAIVAR_SITE_ID
      ? {
          url: process.env.VAIVAR_CENTRAL_URL,
          ingestToken: process.env.VAIVAR_CENTRAL_INGEST_TOKEN,
          siteId: process.env.VAIVAR_SITE_ID,
        }
      : undefined
  );

  const engine = new SessionEngine({
    masterSecret: config.masterSecret,
    budget,
    dwellFlagSeconds: 3600,
    skins: config.skins,
  });

  const bus = new EventBus();

  // Application logger: structured, buffered, rotating. A disk failure here
  // must never crash the process. By default we write it inside the data
  // volume so it survives container restarts; operator overrides are possible
  // via VAIVAR_LOG_PATH.
  const dbPath = resolveDbPath(config.dbPath ?? process.env.DATA_PATH ?? './data/vaivar.db');
  const logPath =
    config.logPath ??
    process.env.VAIVAR_LOG_PATH ??
    path.join(path.dirname(dbPath), 'vaivar.app.log');
  const appLogger = new AppLogger({
    path: logPath,
    maxBytes: 10 * 1024 * 1024,
    maxFiles: 5,
    minLevel: (process.env.VAIVAR_LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error') || 'info',
  });

  const storage = createStorage(dbPath);

  bus.registerSink({
    name: 'log',
    accepts: () => true,
    write: async (e: Event) => {
      appLogger.info('event.raw', { event_type: e.type, session_id: e.session_id });
    },
  });

  // Transversal event log: a unified v2 projection that all sinks consume.
  bus.registerSink(createEventLogSink(appLogger, storage));

  // Attacker activity log: operator-only, no secrets, no seed_id, no flag ids.
  bus.registerSink(createAttackerActivitySink(storage));

  bus.registerSink({
    name: 'storage',
    accepts: () => true,
    write: async (e: Event) => {
      await storage.saveEvent(e);
      if (e.type === 'flag.hit') {
        await storage.saveFlag(e.session_id, e.flag.code, e.flag.level, e.context.node_id);
      }
    },
  });

  // Optional event forwarding never disables the node's private API.
  // External integrations are configured at the central plane only.
  const remote = central
    ? createRemoteEventSink({
        url: central.url,
        token: central.ingestToken,
        siteId: central.siteId,
      })
    : null;
  if (remote) bus.registerSink(remote.asSink());

  let flushTimer: ReturnType<typeof setInterval> | null = null;
  let closing = false;

  const flush = async (): Promise<void> => {
    const { events, sessionEvents } = engine.flushAll();
    const all: Event[] = [...events, ...sessionEvents];
    if (all.length > 0) {
      const eventsWithSite = all.map((e) => (identity?.site_id ? { ...e, site_id: identity.site_id } : e));
      await bus.emitMany(eventsWithSite);
    }
    // KHM-11: persist active sessions to durable storage.
    for (const state of engine.listSessionsRaw()) {
      await engine.persistSession(state);
    }
    // Prune expired sessions from memory and storage.
    await engine.pruneExpired();
  };

  const mcpHandler = config.skins.includes('mcp')
    ? createMCPHandler({
        getSeed: (sessionId: string) => engine.deriveSeed(`mcp-${sessionId}`, 'mcp'),
      })
    : undefined;
  // The public profile can be switched from Central at runtime. Keep its MCP
  // deception handler available even when MCP was not selected for the
  // engine's internal event projection.
  const publicMcpHandler = mcpHandler ?? createMCPHandler({
    getSeed: (sessionId: string) => engine.deriveSeed(`mcp-${sessionId}`, 'mcp'),
  });

  // Resolved at start() once storage is live. Runtime public configuration can
  // be changed by Central and is reflected in the next identity response.
  let identity: NodeIdentity | null = null;
  let honeypotServer: ReturnType<typeof createHoneypotServer>;
  let activeHoneypotPort = honeypotPort;
  let activeHoneypotProfile = initialHoneypotProfile;
  const initialTemplateCheck = validateHoneypotTemplate(config.honeypotTemplate ?? createDefaultTemplate(initialHoneypotProfile));
  if (!initialTemplateCheck.ok) return err(new Error(initialTemplateCheck.error));
  let activeHoneypotTemplate = initialTemplateCheck.template;

  const configureHoneypot = async (params: Record<string, unknown>): Promise<unknown> => {
    const port = params.port;
    const profile = params.profile;
    if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('honeypot port must be an integer between 1 and 65535');
    }
    if (!isHoneypotProfile(profile)) throw new Error('unsupported honeypot service profile');
    if (port === httpPort) throw new Error('honeypot port must differ from the control API port');
    const next = await honeypotServer.configure({ port, profile });
    await storage.saveHoneypotConfig({ honeypot_port: next.port, service_profile: next.profile, template: next.template });
    activeHoneypotPort = next.port;
    activeHoneypotProfile = next.profile;
    activeHoneypotTemplate = next.template;
    if (identity) {
      identity = {
        ...identity,
        honeypot_port: next.port,
        service_profile: next.profile,
        template_id: next.template.id,
        template_version: next.template.version,
      };
    }
    appLogger.info('vaivar.honeypot_configured', {
      honeypotPort: next.port,
      serviceProfile: next.profile,
      siteId: identity?.site_id,
    });
    return {
      action: 'configure_honeypot',
      message: 'Honeypot public surface updated',
      port: next.port,
      profile: next.profile,
      note: 'If Docker publishes a fixed host port, redeploy the port mapping to expose the new listener.',
    };
  };

  const applyHoneypotTemplate = async (params: Record<string, unknown>): Promise<unknown> => {
    const checked = validateHoneypotTemplate(params.template);
    if (!checked.ok) throw new Error(checked.error);
    const next = await honeypotServer.configure({ template: checked.template });
    await storage.saveHoneypotConfig({ honeypot_port: next.port, service_profile: next.profile, template: next.template });
    activeHoneypotTemplate = next.template;
    if (identity) {
      identity = {
        ...identity,
        template_id: next.template.id,
        template_version: next.template.version,
      };
    }
    appLogger.info('vaivar.honeypot_template_applied', {
      templateId: next.template.id,
      templateVersion: next.template.version,
      serviceProfile: next.profile,
      siteId: identity?.site_id,
    });
    return {
      action: 'apply_template',
      message: 'Honeypot template applied',
      template_id: next.template.id,
      template_version: next.template.version,
      profile: next.profile,
    };
  };

  const httpServer = createHTTPServer({
    port: httpPort,
    host: '0.0.0.0',
    engine,
    storage,
    ctiEnabled: false,
    barrierToken: apiToken,
    controlCrypto: config.controlCrypto,
    mcpHandler,
    getNodeIdentity: () => identity,
    onConfigureHoneypot: configureHoneypot,
    onApplyHoneypotTemplate: applyHoneypotTemplate,
    onRestart: async () => {
      appLogger.info('vaivar.restart_requested', { siteId: identity?.site_id });
      try { await flush(); } catch { /* best-effort */ }
      if (flushTimer) clearInterval(flushTimer);
      try { await httpServer.close(); } catch { /* best-effort */ }
      try { await honeypotServer.close(); } catch { /* best-effort */ }
      try { await remote?.flush(); } catch { /* best-effort */ }
      try { await storage.close(); } catch { /* best-effort */ }
      appLogger.shutdown();
      if (typeof config.onRestart === 'function') {
        await config.onRestart();
      } else {
        process.exit(42);
      }
    },
    onRotateChallenges: (newGen: number) => {
      if (typeof config.onRotateChallenges === 'function') {
        config.onRotateChallenges(newGen);
      }
      engine.setChallengeGeneration(newGen);
      appLogger.info('vaivar.challenge_generation_rotated', { generation: newGen });
    },
  });

  honeypotServer = createHoneypotServer({
    port: honeypotPort,
    controlPort: httpPort,
    host: '0.0.0.0',
    engine,
    mcpHandler: publicMcpHandler,
    wikiTitle: 'Documentation',
    openAPITitle: 'API',
    openAPIVersion: '1.0',
    openAPIBasePath: '/v1',
    profile: initialHoneypotProfile,
    template: activeHoneypotTemplate,
  });
  // The server may replace an incompatible startup template with the profile's
  // safe starter template. Keep identity/storage aligned with what is served.
  activeHoneypotTemplate = honeypotServer.template;

  return ok({
    engine,
    bus,
    storage,
    appLogger,
    get nodeIdentity(): NodeIdentity {
      if (!identity) throw new Error('Node identity accessed before start()');
      return identity;
    },
    start: async () => {
      await storage.init();
      const siteId = await storage.getSiteId();
      const bootId = await storage.getBootId();
      const streamId = await storage.getStreamId();
      const generation = await storage.getChallengeGeneration();
      const storedHoneypotConfig = await storage.getHoneypotConfig();
      if (storedHoneypotConfig) {
        await honeypotServer.configure({
          port: storedHoneypotConfig.honeypot_port,
          profile: storedHoneypotConfig.service_profile,
          ...(storedHoneypotConfig.template ? { template: storedHoneypotConfig.template } : {}),
        });
        activeHoneypotPort = honeypotServer.port;
        activeHoneypotProfile = honeypotServer.profile;
        activeHoneypotTemplate = honeypotServer.template;
      }
      // Persist the effective startup configuration too, including a custom
      // deploy template. This makes the first restart behave exactly like a
      // runtime update from Central.
      await storage.saveHoneypotConfig({
        honeypot_port: activeHoneypotPort,
        service_profile: activeHoneypotProfile,
        template: activeHoneypotTemplate,
      });
      // Sync the persisted generation into the engine so new sessions
      // derive seeds under the correct generation immediately.
      engine.setChallengeGeneration(generation);
      // KHM-11: rehydrate active sessions from durable storage.
      await engine.rehydrateFromStorage();
      identity = {
        api_version: 'vaivar.node.v1',
        site_id: siteId,
        boot_id: bootId,
        stream_id: streamId,
        challenge_generation: generation,
        capabilities: NODE_CAPABILITIES,
        control_port: httpPort,
        honeypot_port: activeHoneypotPort,
        service_profile: activeHoneypotProfile,
        control_tls: 'http',
        control_channel: config.controlCrypto ? 'encrypted' : 'legacy',
        template_id: activeHoneypotTemplate.id,
        template_version: activeHoneypotTemplate.version,
      };
      appLogger.info('vaivar.starting', {
        httpPort,
        honeypotPort: activeHoneypotPort,
        serviceProfile: activeHoneypotProfile,
        siteId,
        centralForwarding: Boolean(central),
      });
      await flush();
      flushTimer = setInterval(() => {
        if (!closing) void flush();
      }, config.flushIntervalMs ?? 30_000);
      if (typeof flushTimer.unref === 'function') flushTimer.unref();

      await httpServer.listen();
      await honeypotServer.listen();

      appLogger.info('vaivar.started', {
        httpPort,
        honeypotPort: activeHoneypotPort,
        serviceProfile: activeHoneypotProfile,
        siteId,
        bootId,
        centralForwarding: Boolean(central),
      });
      appLogger.flush();
      return {
        http: { status: 'running', port: httpPort },
        honeypot: { status: 'running', port: activeHoneypotPort },
      };
    },
    stop: async () => {
      if (closing) return;
      closing = true;
      if (flushTimer) clearInterval(flushTimer);
      await httpServer.close();
      await honeypotServer.close();
      try {
        await flush();
      } catch {
        // Best-effort final flush.
      }
      await remote?.flush().catch(() => undefined);
      await storage.close();
      appLogger.shutdown();
    },
    flush,
  });
};
