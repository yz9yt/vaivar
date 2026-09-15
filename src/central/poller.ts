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

// Central polling collector: discovers registered nodes from the registry,
// decrypts their credentials, and polls each node's /api/events endpoint
// using cursor-based pagination. Events are stored in the central store
// keyed by the verified (site_id, stream_id), so equal session IDs on
// different nodes never collide. Cursors are updated per-node independently
// so a crash or timeout on one node cannot stall the rest of the fleet.

import type { StorageIndexer } from '../storage/indexer';
import type { NodeRegistry, CentralNodeRecordWithSecret } from './node-registry';
import type { NodeClient, NodeIdentityResponse, EventPage } from './node-client';
import { persistEvent } from './ingest';
import type { Event } from '../types/events';

/** Map from the central envelope event item to the Event type. */
const mapEnvelopeToEvent = (item: { event_id: string; payload: Record<string, unknown> }, siteId: string): Event | null => {
  const payload = item.payload;

  // Canonical v1 event: use it directly. Do not infer type from event_id.
  if (payload && typeof payload === 'object' && (payload as any).spec === 'vaivar.event.v1' && typeof (payload as any).type === 'string') {
    return payload as unknown as Event;
  }

  // Fallback for legacy v2 projections (should not appear in the canonical
  // feed after the feed-filter fix).
  const eventType = (payload as any)?.type === 'flag.hit' ? 'flag.hit' : 'session.upsert';
  const inner = (payload as any)?.payload as Record<string, unknown> | undefined;
  const source = (payload as any)?.source as Record<string, unknown> | undefined;
  const target = (payload as any)?.target as Record<string, unknown> | undefined;
  const sessionId = (target?.session_id as string) || ((payload as any)?.trace_id as string) || '';

  if (eventType === 'session.upsert') {
    return {
      spec: 'vaivar.event.v1',
      type: 'session.upsert',
      ts: (payload as any)?.ts as string,
      session_id: sessionId,
      site_id: siteId,
      seed_id: inner?.seed_id as string,
      src: {
        ip: source?.ip as string | null,
        userAgent: source?.user_agent as string,
      },
      agent: inner?.agent as any,
      progress: inner?.progress as any,
      intent: inner?.intent as any,
      scores: inner?.scores as any,
      skins: (inner?.skins as string[]) ?? [],
      flags_fired: (inner?.flags_fired as string[]) ?? [],
      severity_hint: inner?.severity_hint as string,
    } as unknown as Event;
  }

  return {
    spec: 'vaivar.event.v1',
    type: 'flag.hit',
    ts: (payload as any)?.ts as string,
    session_id: sessionId,
    site_id: siteId,
    flag: (inner?.flag as any) ?? { code: 'FLAG_LEVEL' as const, level: null, id: '' },
    context: {
      skin: (inner?.skin as string) ?? '',
      node_id: sessionId,
      hint: inner?.hint as string ?? '',
    },
  } as unknown as Event;
};


export interface PollIntervalConfig {
  /** Milliseconds between poll cycles. Default: 30_000 (30 s). */
  readonly intervalMs?: number;
  /** Maximum concurrent node polls. Default: 4. */
  readonly concurrency?: number;
}

export interface NodePollResult {
  readonly site_id: string;
  readonly connected: boolean;
  readonly stream_id: string | null;
  readonly last_cursor: string | null;
  readonly events_collected: number;
  readonly last_error: string | null;
  readonly last_poll_at_ms: number | null;
}

export interface PollerConfig extends PollIntervalConfig {
  readonly registry: NodeRegistry;
  readonly storage: StorageIndexer;
  readonly nodeClient: NodeClient;
}

export interface Poller {
  start(): Promise<void>;
  stop(): Promise<void>;
  getStatus(): NodePollResult[];
  /** Run one synchronous poll cycle across all available nodes. */
  pollOnce(): Promise<void>;
}

export const createPoller = (config: PollerConfig): Poller => {
  const intervalMs = config.intervalMs ?? 30_000;
  const concurrency = Math.max(1, Math.floor(config.concurrency ?? 4));
  let running = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  const activePolls = new Map<string, Promise<void>>();
  const lastResults = new Map<string, NodePollResult>();
  let currentCycle: Promise<void> | null = null;

  /**
   * Decrypt the encrypted secret for a node record. Returns null when
   * the decryption fails (wrong key / tampered record) so the node is
   * marked disconnected rather than crashing the poller.
   */
  const resolveEndpoint = async (
    record: CentralNodeRecordWithSecret
  ): Promise<{ host: string; port: number; token: string; tls: 'http'; channel: 'encrypted' | 'legacy' } | null> => {
    try {
      const token = await config.registry.decryptToken(record.site_id);
      if (!token) return null;
      return {
        host: record.host,
        port: record.port,
        token,
        tls: record.tls ?? 'http',
        channel: record.channel ?? 'legacy',
      };
    } catch {
      return null;
    }
  };

  /**
   * Process one page from a node. Saves events and the cursor
   * atomically. Returns how many new events were saved and the
   * next cursor (null when there is no more data).
   */
  const processPage = async (
    siteId: string,
    streamId: string,
    endpoint: { host: string; port: number; token: string; tls: 'http'; channel: 'encrypted' | 'legacy' },
    cursor: string | null
  ): Promise<{ collected: number; nextCursor: string | null; error: string | null }> => {
    const page = await config.nodeClient.fetchEvents(endpoint, siteId, streamId, cursor);
    if ('kind' in page) {
      return { collected: 0, nextCursor: null, error: page.message };
    }
    const eventPage = page as EventPage;
    if (eventPage.site_id !== siteId && eventPage.site_id !== '') {
      // Identity mismatch — do not advance cursor on a suspicious reply.
      return { collected: 0, nextCursor: null, error: 'stream identity mismatch' };
    }

    let collected = 0;
    let saveError = false;
    for (const item of eventPage.events) {
      const payload = item.payload as Record<string, unknown>;
      const originTs = typeof payload?.ts === 'string'
        ? new Date(payload.ts).getTime()
        : Date.now();
      try {
        await config.storage.saveCentralEvent(
          siteId,
          eventPage.stream_id ?? streamId,
          item.event_id,
          item.sequence,
          originTs,
          (payload?.type as string) ?? 'unknown',
          payload
        );
        const event = mapEnvelopeToEvent(
          { event_id: item.event_id, payload: payload as Record<string, unknown> },
          siteId
        );
        if (event && typeof event === 'object' && 'spec' in event && 'type' in event) {
          await persistEvent(config.storage, event);
        }
        collected += 1;
      } catch (e) {
        console.error(`[poller] error saving event: ${e}`);
        saveError = true;
      }
    }

    // Preserve the server's durable next_cursor even when has_more is false
    // (V-06), and do not advance the cursor if any write failed (V-07).
    const nextCursor = eventPage.next_cursor ?? null;
    if (saveError) {
      await config.storage.savePollCursor(siteId, streamId, cursor, 0);
      return { collected: 0, nextCursor: cursor, error: 'partial save failure' };
    }
    await config.storage.savePollCursor(siteId, streamId, nextCursor, collected);
    await config.storage.updateCentralNodeLastContact(siteId);

    return { collected, nextCursor, error: null };
  };

  /**
   * Single node poll: read current cursor, fetch a page, process it,
   * advance the cursor. Errors are captured so one failing node does
   * not cancel work for other nodes.
   */
  const pollNode = async (record: CentralNodeRecordWithSecret): Promise<NodePollResult> => {
    const endpoint = await resolveEndpoint(record);
    if (!endpoint) {
      return {
        site_id: record.site_id,
        connected: false,
        stream_id: null,
        last_cursor: null,
        events_collected: 0,
        last_error: 'cannot decrypt node credentials',
        last_poll_at_ms: null,
      };
    }

    // Check node identity first.
    const identityResult = await config.nodeClient.fetchIdentity(endpoint);
    if ('kind' in identityResult) {
      return {
        site_id: record.site_id,
        connected: false,
        stream_id: null,
        last_cursor: null,
        events_collected: 0,
        last_error: identityResult.message,
        last_poll_at_ms: null,
      };
    }
    const identity = identityResult as NodeIdentityResponse;

    // Keep the inventory's public-surface metadata authoritative. This also
    // picks up a port/profile changed remotely on the node between polls.
    const runtime: { honeypot_port?: number; service_profile?: string; template_id?: string | null; template_version?: number | null; capabilities?: string[] } = {
      capabilities: identity.capabilities,
    };
    if (typeof identity.honeypot_port === 'number') runtime.honeypot_port = identity.honeypot_port;
    if (typeof identity.service_profile === 'string') runtime.service_profile = identity.service_profile;
    if (identity.template_id !== undefined) runtime.template_id = identity.template_id;
    if (identity.template_version !== undefined) runtime.template_version = identity.template_version;
    await config.registry.updateNodeRuntime(record.site_id, runtime).catch(() => false);

    // Resolve stream from the node's live identity.
    const streamId = identity.stream_id;
    const cursorState = await config.storage.getPollCursor(record.site_id, streamId);
    const cursor = cursorState?.cursor ?? null;

    const { collected, nextCursor, error } = await processPage(
      record.site_id,
      streamId,
      endpoint,
      cursor
    );

    return {
      site_id: record.site_id,
      connected: error === null,
      stream_id: streamId,
      last_cursor: nextCursor,
      events_collected: collected,
      last_error: error,
      last_poll_at_ms: Date.now(),
    };
  };

  const pollNodeTask = (node: CentralNodeRecordWithSecret): Promise<void> => {
    let task!: Promise<void>;
    task = (async () => {
      try {
        const result = await pollNode(node);
        lastResults.set(result.site_id, result);
        if (result.events_collected > 0 || result.last_error) {
          console.log(`[poller] site=${result.site_id} connected=${result.connected} collected=${result.events_collected} error=${result.last_error ?? 'none'} stream=${result.stream_id}`);
        }
      } catch (error) {
        const result: NodePollResult = {
          site_id: node.site_id,
          connected: false,
          stream_id: null,
          last_cursor: null,
          events_collected: 0,
          last_error: error instanceof Error ? error.message : 'poll failed',
          last_poll_at_ms: Date.now(),
        };
        lastResults.set(node.site_id, result);
        console.error(`[poller] site=${node.site_id} poll failed: ${result.last_error}`);
      } finally {
        if (activePolls.get(node.site_id) === task) activePolls.delete(node.site_id);
      }
    })();
    activePolls.set(node.site_id, task);
    return task;
  };

  const runCycleBody = async (): Promise<void> => {
    const nodes = await config.registry.listNodes();
    let nextNode = 0;
    const worker = async (): Promise<void> => {
      while (nextNode < nodes.length) {
        const node = nodes[nextNode++];
        if (node) await pollNodeTask(node);
      }
    };
    const workers = Math.min(concurrency, nodes.length);
    await Promise.all(Array.from({ length: workers }, () => worker()));
  };

  const runCycle = async (): Promise<void> => {
    if (currentCycle) return currentCycle;
    currentCycle = runCycleBody();
    const cycle = currentCycle;
    try {
      await cycle;
    } finally {
      if (currentCycle === cycle) currentCycle = null;
    }
  };

  return {
    start: async () => {
      if (running) return;
      running = true;
      await runCycle();
      timer = setInterval(() => {
        if (!running) return;
        void runCycle().catch(() => undefined);
      }, intervalMs);
      if (typeof timer.unref === 'function') timer.unref();
    },
    stop: async () => {
      running = false;
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      // Wait for in-flight polls to settle.
      const cycle = currentCycle;
      if (cycle) await cycle.catch(() => undefined);
      if (activePolls.size > 0) await Promise.allSettled(Array.from(activePolls.values()));
    },
    pollOnce: runCycle,
    getStatus: (): NodePollResult[] => {
      return Array.from(lastResults.values());
    },
  };
};
