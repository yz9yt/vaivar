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

import type { StorageIndexer } from '../storage/indexer';
import type { AttackerActivityRecord } from '../storage/types';
import type { Event } from '../types/events';
import type { OpenCTIConnector } from '../cti/connector';
import { normalizeEvent, projectAttackerActivity, isAttackerEvent } from '../logging/eventlog';

/**
 * Persist one forwarded event into the central store:
 *  - events table (deduped by deterministic id)
 *  - flags table (for flag.hit)
 *  - attacker_activity table (sanitized, no seed/flag ids)
 * Storage failures are best-effort so a downstream outage can't stall
 * the Edge push.
 */
export const persistEvent = async (
  storage: StorageIndexer,
  event: Event,
  openCTIConnectors?: Map<string, OpenCTIConnector>
): Promise<void> => {
  await storage.saveEvent(event);

  if (event.type === 'flag.hit') {
    try {
      await storage.saveFlag(event.session_id, event.flag.code, event.flag.level, event.context.node_id);
    } catch {
      // Non-fatal.
    }
  }

  if (!isAttackerEvent(event)) return;

  const src = (event as { src?: { ip?: string; userAgent?: string } }).src;
  const agent = (event as { agent?: { class?: string; confidence?: number; tooling?: unknown } }).agent;
  const envelope = normalizeEvent(event, {
    source: {
      type: 'attacker',
      ip: event.type === 'session.upsert' ? src?.ip ?? null : null,
      user_agent: event.type === 'session.upsert' ? src?.userAgent ?? '' : '',
      path: event.type === 'flag.hit' ? event.context?.node_id : undefined,
    },
  });
  const classifier = event.type === 'session.upsert' && agent
    ? { class: agent.class, confidence: agent.confidence, tools: agent.tooling as string[] | undefined }
    : undefined;
  const activity = projectAttackerActivity(envelope, classifier);
  const payload = { ...envelope.payload } as Record<string, unknown>;
  delete payload.seed_id;
  delete payload.flag;

  const record: AttackerActivityRecord = {
    id: activity.id,
    ts: new Date(activity.ts).getTime(),
    session_id: activity.session_id,
    site_id: event.site_id ?? null,
    event_type: activity.event_type,
    ip: activity.ip ?? null,
    user_agent: activity.user_agent ?? '',
    path: activity.path ?? null,
    classification: activity.classification ?? null,
    confidence: activity.confidence ?? null,
    tooling: activity.tooling ? JSON.stringify(activity.tooling) : null,
    level_max: activity.level_max ?? null,
    flags_fired: activity.flags_fired ? JSON.stringify(activity.flags_fired) : null,
    win_isolated: activity.win_isolated ?? null,
    meta_detect: activity.meta_detect ?? null,
    capability: activity.capability ?? null,
    intent: activity.intent ?? null,
    severity: activity.severity ?? null,
    payload_json: JSON.stringify(payload),
  };

  try {
    await storage.saveAttackerActivity(record);
  } catch {
    // Non-fatal.
  }

  // Forward to OpenCTI connectors (fire-and-forget: never blocks ingest).
  if (openCTIConnectors && openCTIConnectors.size > 0) {
    for (const connector of openCTIConnectors.values()) {
      void connector.handleEvent(event).catch(() => undefined);
    }
  }
};
