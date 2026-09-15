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

// Transversal event envelope: a unified, versioned projection that hides
// implementation details and lets multiple sinks (app log, attacker log, CTI)
// consume the same schema without coupling to vaivar.event.v1 internals.

import type { Event } from '../types/events';

export const EVENT_SCHEMA_VERSION = 2;

export interface EventEnvelope {
  readonly spec: 'vaivar.event.v2';
  readonly schema_version: typeof EVENT_SCHEMA_VERSION;
  readonly event_id: string;
  readonly ts: string;
  readonly created_at: string;
  readonly trace_id: string;
  readonly correlation_id?: string;
  readonly category: 'session' | 'flag' | 'meta_probe' | 'system';
  readonly source: {
    type: 'application' | 'attacker' | 'system';
    ip?: string | null;
    user_agent?: string;
    method?: string;
    path?: string;
  };
  readonly target: {
    session_id: string;
    node_id?: string;
    skin?: string;
  };
  readonly payload: {
    event_type: string;
    [key: string]: unknown;
  };
  readonly redaction: 'none' | 'attacker' | 'operator';
}

export interface AttackerActivityRecord {
  readonly id: string;
  readonly ts: string;
  readonly session_id: string;
  readonly event_type: string;
  readonly ip: string | null;
  readonly user_agent: string;
  readonly path?: string;
  readonly classification?: string;
  readonly confidence?: number;
  readonly tooling?: string[];
  readonly level_max?: number;
  readonly flags_fired?: string[];
  readonly win_isolated?: boolean;
  readonly meta_detect?: boolean;
  readonly capability?: number;
  readonly intent?: number;
  readonly severity?: string;
}

/**
 * Normalize a vaivar.event.v1 into a v2 envelope. The envelope is the single
 * source of truth for all external sinks.
 */
export const normalizeEvent = (
  event: Event,
  opts: { traceId?: string; correlationId?: string; source?: EventEnvelope['source'] } = {}
): EventEnvelope => {
  const createdAt = new Date().toISOString();
  const sessionId = event.session_id;

  if (event.type === 'session.upsert') {
    return {
      spec: 'vaivar.event.v2',
      schema_version: EVENT_SCHEMA_VERSION,
      event_id: `e_${sessionId.slice(0, 8)}_upsert`,
      ts: event.ts,
      created_at: createdAt,
      trace_id: opts.traceId ?? sessionId,
      correlation_id: opts.correlationId,
      category: 'session',
      source: {
        type: opts.source?.type ?? 'attacker',
        ip: event.src.ip,
        user_agent: event.src.userAgent,
        method: opts.source?.method,
        path: opts.source?.path,
      },
      target: {
        session_id: sessionId,
        node_id: opts.source?.path?.split('/').pop(),
      },
      payload: {
        event_type: event.type,
        seed_id: event.seed_id,
        agent: event.agent,
        progress: event.progress,
        intent: event.intent,
        scores: event.scores,
        skins: event.skins,
        flags_fired: event.flags_fired,
        severity_hint: event.severity_hint,
      },
      redaction: 'attacker',
    };
  }

  if (event.type === 'flag.hit') {
    return {
      spec: 'vaivar.event.v2',
      schema_version: EVENT_SCHEMA_VERSION,
      event_id: `e_${sessionId.slice(0, 8)}_flag`,
      ts: event.ts,
      created_at: createdAt,
      trace_id: opts.traceId ?? sessionId,
      correlation_id: opts.correlationId,
      category: 'flag',
      source: {
        type: opts.source?.type ?? 'attacker',
        ip: opts.source?.ip,
        user_agent: opts.source?.user_agent,
        method: opts.source?.method,
        path: event.context.node_id,
      },
      target: {
        session_id: sessionId,
        node_id: event.context.node_id,
        skin: event.context.skin,
      },
      payload: {
        event_type: event.type,
        flag: event.flag,
        context: event.context,
      },
      redaction: 'attacker',
    };
  }

  // Fallback for unknown event types
  return {
    spec: 'vaivar.event.v2',
    schema_version: EVENT_SCHEMA_VERSION,
    event_id: `e_${Date.now()}`,
    ts: new Date().toISOString(),
    created_at: createdAt,
    trace_id: opts.traceId ?? 'unknown',
    category: 'system',
    source: { type: 'system' },
    target: { session_id: sessionId },
    payload: { event_type: 'unknown', raw: event },
    redaction: 'operator',
  };
};

/**
 * Project an event envelope into an attacker-facing activity record.
 * Removes any fields that could leak operator secrets.
 */
export const projectAttackerActivity = (
  envelope: EventEnvelope,
  classifier?: { class?: string; confidence?: number; tools?: string[] }
): AttackerActivityRecord => {
  const payload = envelope.payload as Record<string, unknown>;
  const progress = payload.progress as Record<string, unknown> | undefined;
  const scores = payload.scores as Record<string, unknown> | undefined;

  return {
    id: envelope.event_id,
    ts: envelope.ts,
    session_id: envelope.target.session_id,
    event_type: envelope.payload.event_type,
    ip: envelope.source.ip ?? null,
    user_agent: envelope.source.user_agent ?? '',
    path: envelope.source.path,
    classification: classifier?.class,
    confidence: classifier?.confidence,
    tooling: classifier?.tools,
    level_max: (progress?.level_max as number) ?? undefined,
    flags_fired: (payload.flags_fired as string[]) ?? undefined,
    win_isolated: (progress?.win_isolated as boolean) ?? undefined,
    meta_detect: (progress?.meta_detect as boolean) ?? undefined,
    capability: (scores?.capability as number) ?? undefined,
    intent: (scores?.intent as number) ?? undefined,
    severity: payload.severity_hint as string | undefined,
  };
};

export const isAttackerEvent = (event: Event): boolean =>
  event.type === 'session.upsert' || event.type === 'flag.hit';
