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
import path from 'path';
import { randomBytes } from 'crypto';
import { createCentralServer } from './server';
import { createStorage } from '../storage/indexer';
import type { StorageIndexer } from '../storage/indexer';
import { createNodeClient } from './node-client';
import { createNodeRegistry } from './node-registry';
import { createPoller } from './poller';
import { createSplunkHecAdapter, type SplunkHecAdapter } from './splunk-hec';
import { projectHecEvent } from './splunk-events';
import { createOpenCTIConnector, type OpenCTIConnector, type OpenCTIConfig } from '../cti/connector';
import type { EventEnvelope } from '../logging/eventlog';
import { DEFAULT_TEMPLATES } from '../templates/defaults';
import { newerReleaseExists, newestStableRelease, formatUpdateNotice, createReleaseCatalog } from './update-check';
import { VAIVAR_VERSION } from '../version';

const generateKey = (): string => randomBytes(32).toString('hex');

export interface SplunkHecCentralConfig {
  /** Splunk HEC URL, e.g. https://splunk.example.com:8088/services/collector. */
  readonly url: string;
  /** HEC token. */
  readonly token: string;
  /** Optional index sent on every event. */
  readonly index?: string;
  /** Optional source sent on every event. */
  readonly source?: string;
  /** Optional sourcetype override. */
  readonly sourcetype?: string;
  /** Max retry attempts on a failing batch. */
  readonly maxRetries?: number;
  /** Max queued events before dropping oldest. */
  readonly maxQueue?: number;
  /** Batch size per POST. */
  readonly batchSize?: number;
  /** Request timeout in ms. */
  readonly timeoutMs?: number;
}

export interface OpenCTICentralConfig {
  /** OpenCTI base URL, e.g. https://opencti.example.com. */
  readonly url: string;
  /** API token for EXTERNAL_IMPORT connector. */
  readonly token: string;
  /** Optional confidence level for STIX objects. */
  readonly confidence?: number;
  /** Optional organization id to scope data. */
  readonly organizationId?: string;
  /** Max retry attempts for a failing bundle. */
  readonly maxRetries?: number;
  /** Max queued bundles when OpenCTI is unreachable. */
  readonly maxQueue?: number;
}

export interface CentralAppConfig {
  readonly port: number;
  readonly host: string;
  readonly ingestToken: string;
  readonly operatorToken: string;
  /** Token for admin-level actions (node enrollment, commands). */
  readonly adminToken?: string;
  /** Token for superadmin (total control). Optional. */
  readonly superadminToken?: string;
  /** Break-glass token (>=16 chars) that logs in as superadmin when
   *  Keycloak is unavailable. Optional. */
  readonly bootstrapToken?: string;
  /** Key used to sign the Central session cookie (>=32 hex). */
  readonly sessionKey?: string;
  /** Key used to encrypt stored node tokens. If absent, a random per-run
   * key is generated (fine for dev, not for prod). */
  readonly centralKey?: string;
  readonly dbPath: string;
  readonly retentionDays?: number;
  /** When true, the operator dashboard and its API are served without auth. */
  readonly devMode?: boolean;
  /** Auth mode for UI/API access: "none" (default, open), "legacy" (token login), "oidc" (Keycloak SSO). */
  readonly authMode?: 'none' | 'legacy' | 'oidc';
  /** Trust x-forwarded-for for client-IP derivation (only behind a trusted proxy). */
  readonly trustProxy?: boolean;
  /** Polling interval in milliseconds (default: 30000). */
  readonly pollIntervalMs?: number;
  /** Maximum concurrent node polls (default: 4). */
  readonly pollConcurrency?: number;
  /** Optional Splunk HEC export configuration. */
  readonly splunk?: SplunkHecCentralConfig;
  /** Optional OpenCTI bootstrap configuration (fallback; persisted
   * integration_settings take precedence). */
  readonly openCTI?: OpenCTICentralConfig;
  /** Directory containing central-approved release bundles. */
  readonly releaseDir?: string;
  /** Host-side installer served to an authorized bootstrap client. */
  readonly installerPath?: string;
  /** When true, skip the "new version available" advisory at startup. */
  readonly noUpdateCheck?: boolean;
  /** When true, allow private (RFC1918/loopback/link-local) hosts in node enrollment and integration URLs. Use when Central and Edge share a LAN. */
  readonly allowPrivateHosts?: boolean;
}

export interface CentralApp {
  readonly storage: StorageIndexer;
  readonly registry: ReturnType<typeof createNodeRegistry>;
  /** The Splunk HEC adapter, if configured. */
  readonly splunkHec?: SplunkHecAdapter;
  /** OpenCTI connectors by configuration name, if any are enabled. */
  readonly openCTIConnectors: Map<string, OpenCTIConnector>;
  readonly poller: ReturnType<typeof createPoller>;
  readonly start: () => Promise<void>;
  readonly stop: () => Promise<void>;
}

/**
 * Register a Splunk HEC sink that projects every persisted envelope onto
 * a HEC event and forwards it to the adapter. The sink is registered on
 * the central storage's internal event bus so it is invoked for every
 * persisted event, not only for events polled from nodes.
 *
 * The sink is intentionally fire-and-forget: a Splunk outage must never
 * block the central ingest pipeline. The adapter keeps the bounded queue
 * and retry state; delivery progress is reconciled by the central poller.
 */
const registerSplunkHecSink = (adapter: SplunkHecAdapter, siteId: string): { write: (e: EventEnvelope) => Promise<void> } => {
  return {
    write: async (envelope: EventEnvelope) => {
      if (!adapter.enabled) return;
      const event = projectHecEvent(envelope, { siteId }, Date.now());
      if (!event) return;
      await adapter.accept(event);
    },
  };
};

const resolveDbPath = (raw: string): string => {
  if (raw === ':memory:' || raw.endsWith('.db') || raw.endsWith('.sqlite')) return raw;
  try {
    const st = fs.statSync(raw);
    if (st.isDirectory()) return path.join(raw, 'vaivar.db');
  } catch {
    // Treat as a file path; the storage layer creates parent dirs.
  }
  // If it looks like a directory (e.g. a mounted volume path without an
  // extension), append the db filename so better-sqlite3 opens a file.
  if (!path.extname(raw)) return path.join(raw, 'vaivar.db');
  return raw;
};

export const bootstrapCentral = async (config: CentralAppConfig): Promise<CentralApp> => {
  const storage = createStorage({ path: resolveDbPath(config.dbPath), retentionDays: config.retentionDays ?? 90 });
  const nodeClient = createNodeClient();
  const registry = createNodeRegistry(storage, config.centralKey ?? generateKey(), nodeClient);

  // Central polling collector: pulls events from every registered node
  // using cursor-based pagination. Runs independently of the HTTP server
  // so a node outage cannot stall the central plane.
  const poller = createPoller({
    registry,
    storage,
    nodeClient,
    intervalMs: config.pollIntervalMs,
    concurrency: config.pollConcurrency,
  });

  // Prepare Splunk HEC adapter if configured.
  let splunkHec: SplunkHecAdapter | undefined;
  if (config.splunk) {
    const siteId = await storage.getSiteId().catch(() => 'unknown');
    splunkHec = createSplunkHecAdapter({
      url: config.splunk.url,
      token: config.splunk.token,
      index: config.splunk.index,
      source: config.splunk.source,
      sourcetype: config.splunk.sourcetype,
      maxRetries: config.splunk.maxRetries,
      maxQueue: config.splunk.maxQueue,
      batchSize: config.splunk.batchSize,
      timeoutMs: config.splunk.timeoutMs,
    });
    // Register the HEC sink so every incoming envelope is forwarded.
    // The sink lives on the central side only — nodes never talk to Splunk.
    const splunkSink = registerSplunkHecSink(splunkHec, siteId);
    // Store the sink reference so it's never GC'd.
    (storage as any).__splunkSink = splunkSink;
  }

  // Load OpenCTI connectors from integration settings (persisted config).
  // Bootstrap env vars are used as fallback when no persisted config exists.
  const openCTIConnectors = new Map<string, OpenCTIConnector>();
  const loadOpenCTIConnectors = async (): Promise<void> => {
    const settings = await storage.listIntegrationSettings();
    for (const setting of settings) {
      if (setting.kind !== 'cti' || !setting.enabled) continue;
      let cfg: OpenCTIConfig | undefined;
      try { cfg = JSON.parse(setting.config_json) as OpenCTIConfig; } catch { /* malformed */ }
      if (!cfg?.url || !cfg.token) continue;
      openCTIConnectors.set(setting.name, createOpenCTIConnector(cfg));
    }
    // Fall back to env vars if no persisted config loaded.
    if (openCTIConnectors.size === 0 && config.openCTI) {
      openCTIConnectors.set('default', createOpenCTIConnector(config.openCTI));
    }
  };
  await loadOpenCTIConnectors();

  // Build the local release catalog once (best-effort; empty dir is valid).
  const releaseCatalog = config.releaseDir ? createReleaseCatalog(config.releaseDir) : undefined;

  const server = createCentralServer({
    port: config.port,
    host: config.host,
    storage,
    ingestToken: config.ingestToken,
    operatorToken: config.operatorToken,
    adminToken: config.adminToken,
    superadminToken: config.superadminToken,
    centralKey: config.centralKey,
    bootstrapToken: config.bootstrapToken,
    sessionKey: config.sessionKey,
    nodeClient,
    nodeRegistry: registry,
    poller,
    openCTIConnectors,
    releaseDir: config.releaseDir,
    installerPath: config.installerPath,
    devMode: config.devMode,
    authMode: config.authMode,
    allowPrivateHosts: config.allowPrivateHosts,
    trustProxy: config.trustProxy,
  });

  let closing = false;
  const stop = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    if (retentionTimer) {
      clearInterval(retentionTimer);
      retentionTimer = null;
    }
    await poller.stop();
    await server.close();
    await storage.close();
  };

  let retentionTimer: ReturnType<typeof setInterval> | null = null;

  return {
    storage,
    registry,
    openCTIConnectors,
    poller,
    start: async () => {
      await storage.init();
      // Seed useful starter templates once. They are ordinary catalog rows,
      // so an operator can publish later versions without changing the node
      // image or overwriting a customized template.
      const existingTemplates = await storage.listHoneypotTemplates();
      const existingKeys = new Set(existingTemplates.map((item) => `${item.id}:${item.version}`));
      for (const template of DEFAULT_TEMPLATES) {
        if (!existingKeys.has(`${template.id}:${template.version}`)) {
          await storage.saveHoneypotTemplate(template);
        }
      }
      // Periodic retention enforcement (default 90 days). Keeps the central
      // store lean and bounds disk usage across sites.
      retentionTimer = setInterval(() => {
        void storage.pruneOldData().catch(() => undefined);
      }, 6 * 60 * 60 * 1000);
      if (typeof retentionTimer.unref === 'function') retentionTimer.unref();
      await server.listen();
      // Start polling after the server is up so the first cycle can run.
      await poller.start();
      // Fire-and-forget advisory: warn once if a newer stable release exists.
      if (!config.noUpdateCheck && releaseCatalog && newerReleaseExists(releaseCatalog, VAIVAR_VERSION)) {
        const latest = newestStableRelease(releaseCatalog);
        if (latest) console.warn(formatUpdateNotice(VAIVAR_VERSION, latest));
      }
    },
    stop,
  };
};
