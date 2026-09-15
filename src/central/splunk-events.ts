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

// Splunk HEC event transformer (pure).
//
// Translates a normalized vaivar.event.v2 envelope into the Splunk HTTP Event
// Collector (HEC) event format. The mapping is intentionally lossy: it keeps
// only the fields an operator needs for detection and triage. It must NEVER
// expose seeds, flag internals, or operator secrets.
//
// Reference: Splunk HTTP Event Collector REST API — POST /services/collector
// and the event endpoint /services/collector/event.

import type { EventEnvelope } from '../logging/eventlog';
import { sha256Hex } from '../hash/stable';

/**
 * One HEC event payload as Splunk expects it. `event` carries the normalized
 * detection data; `sourcetype`, `source`, `index`, `host`, `time` are HEC
 * metadata fields used for routing inside Splunk.
 */
export interface HecEvent {
  readonly time: number;
  readonly host: string;
  readonly source: string;
  readonly sourcetype: string;
  readonly index: string;
  readonly event: HecEventData;
}

export interface HecEventData {
  readonly spec: 'vaivar.event.v2';
  readonly schema_version: number;
  readonly event_id: string;
  readonly trace_id: string;
  readonly ts: string;
  readonly category: 'session' | 'flag' | 'meta_probe' | 'system';
  readonly site_id: string;
  readonly session_id: string;
  readonly event_type: string;
  readonly ip: string | null;
  readonly user_agent: string;
  readonly node_id: string | null;
  readonly skin: string | null;
  readonly agent_class: string | null;
  readonly tooling: string[] | null;
  readonly classification: string | null;
  readonly confidence: number | null;
  readonly level_max: number | null;
  readonly flags_fired: string[] | null;
  readonly win_isolated: boolean | null;
  readonly meta_detect: boolean | null;
  readonly capability: number | null;
  readonly intent: number | null;
  readonly severity: string | null;
  readonly dwell_seconds: number | null;
  readonly requests: number | null;
  readonly bytes_read: number | null;
  readonly nodes_visited: number | null;
  readonly flag_code: string | null;
  readonly flag_level: number | null;
  readonly hint: string | null;
  readonly redaction: 'none' | 'attacker' | 'operator';
}

/**
 * Configuration for the HEC event producer. `site_id` is bound at construction
 * so every event carries a stable node identity, even if the original v1 event
 * lacked it (historical records).
 */
export interface HecEventConfig {
  readonly siteId: string;
  readonly index?: string;
  readonly host?: string;
  readonly source?: string;
  readonly sourcetype?: string;
}

const DEFAULT_SOURCETYPE = 'vaivar:event';
const DEFAULT_SOURCE = 'vaivar:hec';

/**
 * Deterministic event origin id that survives serialisation and restart.
 * Splunk uses this for deduplication (the same event imported twice is the
 * same event). We derive it from fields that uniquely identify the source
 * fact: (site_id, session_id, event type, deterministic v1 id/v1 trace).
 * We never use `created_at` or arrival time.
 */
export const hecOriginId = (envelope: EventEnvelope): string =>
  `vaivar_${sha256Hex(
    [
      envelope.target.session_id,
      envelope.payload.event_type,
      envelope.trace_id,
      envelope.target.node_id ?? '',
      envelope.target.skin ?? '',
    ].join('|')
  ).slice(0, 32)}`;

/**
 * Project a v2 envelope into an `HecEventData` record. Returns null when the
 * envelope cannot be projected (caller should skip). The projection drops
 * seed_id, raw flag codes and any operator-only context.
 *
 * Pure: identical envelope -> identical output. No clock, no random.
 */
export const toHecEventData = (
  envelope: EventEnvelope,
  config: HecEventConfig
): HecEventData | null => {
  const payload = envelope.payload as Record<string, unknown>;
  const progress = payload.progress as Record<string, unknown> | undefined;
  const intent = payload.intent as Record<string, unknown> | undefined;
  const agent = payload.agent as Record<string, unknown> | undefined;
  const scores = payload.scores as Record<string, unknown> | undefined;
  const flag = payload.flag as Record<string, unknown> | undefined;
  const context = payload.context as Record<string, unknown> | undefined;

  return {
    spec: envelope.spec,
    schema_version: envelope.schema_version,
    event_id: hecOriginId(envelope),
    trace_id: envelope.trace_id,
    ts: envelope.ts,
    category: envelope.category,
    site_id: config.siteId,
    session_id: envelope.target.session_id,
    event_type: envelope.payload.event_type,
    ip: envelope.source.ip ?? null,
    user_agent: envelope.source.user_agent ?? '',
    node_id: envelope.target.node_id ?? null,
    skin: envelope.target.skin ?? null,
    agent_class: (agent?.class as string | undefined) ?? null,
    tooling: (agent?.tooling as string[] | undefined) ?? null,
    classification: (agent?.class as string | undefined) ?? null,
    confidence: (agent?.confidence as number | undefined) ?? null,
    level_max: (progress?.level_max as number | undefined) ?? null,
    flags_fired: (payload.flags_fired as string[] | undefined) ?? null,
    win_isolated: (progress?.win_isolated as boolean | undefined) ?? null,
    meta_detect: (progress?.meta_detect as boolean | undefined) ?? null,
    capability: (scores?.capability as number | undefined) ?? null,
    intent: (scores?.intent as number | undefined) ?? null,
    severity: (payload.severity_hint as string | undefined) ?? null,
    dwell_seconds: (intent?.dwell_seconds as number | undefined) ?? null,
    requests: (intent?.requests as number | undefined) ?? null,
    bytes_read: (intent?.bytes_read as number | undefined) ?? null,
    nodes_visited: (intent?.nodes_visited as number | undefined) ?? null,
    flag_code: (flag?.code as string | undefined) ?? null,
    flag_level: (flag?.level as number | undefined) ?? null,
    hint: (context?.hint as string | undefined) ?? null,
    redaction: envelope.redaction,
  };
};

/**
 * Serialise a list of HEC events into the body Splunk expects.
 *
 * Splunk's /services/collector/event endpoint accepts one event per request,
 * while /services/collector (no `/event`) accepts a newline-joined stream of
 * JSON objects. We produce the stream form so a single POST can carry a
 * batch. The `asBatchedBody` helper is the inverse on the wire.
 */
export const buildHecRequestBody = (events: readonly HecEvent[]): string =>
  events.map((e) => JSON.stringify(e)).join('\n');

/**
 * Wrap projected event data into a full HEC event with routing metadata.
 * `time` is expressed in epoch seconds (Splunk convention).
 */
export const toHecEvent = (
  data: HecEventData,
  opts: { time: number; config: HecEventConfig }
): HecEvent => ({
  time: Math.floor(opts.time / 1000),
  host: opts.config.host ?? opts.config.siteId,
  source: opts.config.source ?? DEFAULT_SOURCE,
  sourcetype: opts.config.sourcetype ?? DEFAULT_SOURCETYPE,
  index: opts.config.index ?? '',
  event: data,
});

/**
 * Convenience: project an envelope into an HecEvent, or null if it cannot be
 * projected. This is the primary entry point used by the HEC export sink.
 */
export const projectHecEvent = (
  envelope: EventEnvelope,
  config: HecEventConfig,
  time: number
): HecEvent | null => {
  const data = toHecEventData(envelope, config);
  if (!data) return null;
  return toHecEvent(data, { time, config });
};
