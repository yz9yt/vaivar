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

import type { Event } from '../types/events';
import { normalizeEvent, projectAttackerActivity } from './eventlog';
import type { AppLogger } from './applog';
import type { StorageIndexer } from '../storage/indexer';

export const createEventLogSink = (logger: AppLogger, storage?: StorageIndexer): EventSinkLike => ({
  name: 'event_log',
  accepts: () => true,
  write: async (event: Event) => {
    const envelope = normalizeEvent(event);
    logger.info('event.transversal', {
      event_id: envelope.event_id,
      schema_version: envelope.schema_version,
      category: envelope.category,
      session_id: envelope.target.session_id,
      event_type: envelope.payload.event_type,
      redaction: envelope.redaction,
    });

    if (storage) {
      // Persist the normalized projection too. The raw v1 event remains in the
      // event store for replay; the v2 projection is the stable cross-cutting
      // schema used by external consumers.
      try {
        await storage.saveEventEnvelope?.(envelope);
      } catch {
        // Storage failure is non-fatal; the app log remains available.
      }
    }
  },
});

export interface EventSinkLike {
  readonly name: string;
  accepts: (e: Event) => boolean;
  write: (e: Event) => Promise<void>;
}

export const createAttackerActivitySink = (storage: StorageIndexer): EventSinkLike => ({
  name: 'attacker_activity',
  accepts: (event) => event.type === 'session.upsert' || event.type === 'flag.hit',
  write: async (event) => {
    const envelope = normalizeEvent(event);
    const payload = envelope.payload as Record<string, unknown>;
    const activity = projectAttackerActivity(envelope, event.type === 'session.upsert'
      ? {
          class: (payload.agent as { class?: string } | undefined)?.class,
          confidence: (payload.scores as { confidence?: number } | undefined)?.confidence,
          tools: (payload.agent as { tooling?: string[] } | undefined)?.tooling,
        }
      : undefined);

    // Strip sensitive fields before persistence.
    const { seed_id: _seedId, flag: _flag, ...safePayload } = payload;
    const record = {
      id: activity.id,
      session_id: activity.session_id,
      ts: new Date(envelope.ts).getTime(),
      event_type: activity.event_type,
      ip: activity.ip ?? null,
      user_agent: activity.user_agent ?? '',
      path: envelope.source.path ?? null,
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
      payload_json: JSON.stringify(safePayload),
    };

    try {
      await storage.saveAttackerActivity(record);
    } catch {
      // Storage failure must not affect event delivery.
    }
  },
});
