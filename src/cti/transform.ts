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

import type { SessionEvent, FlagEvent, Event } from '../types/events';
import {
  generateSTIXId,
  isIndicatorCandidate,
  validateAsIndicator,
} from './ids';

export interface STIXBundle {
  readonly type: 'bundle';
  readonly id: string;
  readonly objects: readonly unknown[];
}

export interface STIXIncident {
  readonly type: 'incident';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly created: string;
  readonly modified: string;
  readonly name: string;
  readonly description: string;
  readonly severity: string;
  readonly labels: string[];
  readonly external_references: Array<{ source_name: string; description: string }>;
  readonly object_marking_refs: string[];
  readonly extensions: Record<string, unknown>;
}

export interface STIXTool {
  readonly type: 'tool';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly name: string;
  readonly description: string;
}

export interface STIXUrl {
  readonly type: 'url';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly value: string;
  readonly labels: string[];
  readonly x_generated: boolean;
}

export interface STIXIp {
  readonly type: 'ipv4-addr' | 'ipv6-addr';
  readonly spec_version: '2.1';
  readonly id: string;
  readonly value: string;
  readonly labels: string[];
}

const severityMap: Record<string, string> = {
  info: 'low',
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'high',
};

/** Session event -> STIX incident (no real PII, no seed leakage). */
export const sessionToIncident = (event: SessionEvent): STIXIncident => {
  const name = `Agent session ${event.session_id}`;
  const ip = event.src.ip;
  return {
    type: 'incident',
    spec_version: '2.1',
    id: generateSTIXId('incident', event.session_id),
    created: event.ts,
    modified: event.ts,
    name,
    description: `Agent session from ${ip ?? 'unknown'} (${event.agent.class})`,
    severity: severityMap[event.severity_hint] ?? 'medium',
    labels: ['vaivar'],
    external_references: [],
    object_marking_refs: [],
    extensions: {
      'x-vaivar': {
        session_id: event.session_id,
        seed_id: event.seed_id,
        capability: event.scores.capability,
        intent: event.scores.intent,
        level_max: event.progress.level_max,
        dwell_seconds: event.intent.dwell_seconds,
        win_isolated: event.progress.win_isolated,
        meta_detect: event.progress.meta_detect,
        skins: event.skins,
        flags_fired: event.flags_fired,
      },
    },
  };
};

/**
 * Agent session -> STIX bundle.
 * - Real attacker IP becomes an indicator ONLY if validateAsIndicator says so.
 * - Maze URLs are correlation observables, never indicators.
 * - Tooling becomes a tool observable.
 * - Flags (LEVEL/DWELL/WIN) are internal evidence: NEVER indicators.
 */
export const sessionToStixBundle = (event: SessionEvent): STIXBundle => {
  const objects: unknown[] = [sessionToIncident(event)];

  if (event.src.ip && isIndicatorCandidate({ type: 'ipv4-addr', labels: [] })) {
    const fact = validateAsIndicator({ type: 'ipv4-addr', value: event.src.ip });
    if (fact.isIndicator) {
      objects.push({
        type: event.src.ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
        spec_version: '2.1',
        id: generateSTIXId(event.src.ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr', event.src.ip),
        value: event.src.ip,
        labels: ['attacker-infrastructure'],
      } satisfies STIXIp);
    }
  }

  const toolNames = event.agent.tooling.filter((t) => t && t !== 'unknown');
  toolNames.forEach((tool) => {
    objects.push({
      type: 'tool',
      spec_version: '2.1',
      id: generateSTIXId('tool', tool),
      name: tool,
      description: `Inferred tooling for session ${event.session_id}`,
    } satisfies STIXTool);
  });

  // Maze URLs are correlation only; never indicators.
  objects.push({
    type: 'note',
    spec_version: '2.1',
    id: generateSTIXId('note', `maze-${event.session_id}`),
    abstract: 'Correlation note: generated maze paths for this session are not indicators.',
    content: `Maze URL set for session ${event.session_id} is internal evidence only.`,
    object_marking_refs: ['https://inlinelisting.opencti.io/marking/definition/open-sources'],
  });

  return { type: 'bundle', id: generateSTIXId('bundle', event.session_id), objects };
};

/** Flag event -> internal evidence note (never an indicator). */
export const flagToStixBundle = (event: FlagEvent): STIXBundle => {
  const fact = { type: `flag:${event.flag.code}` } as { type: string };
  const policy = validateAsIndicator(fact);
  if (policy.isIndicator) return { type: 'bundle', id: 'bundle--invalid', objects: [] };

  return {
    type: 'bundle',
    id: generateSTIXId('bundle', `${event.flag.id}-evidence`),
    objects: [
      {
        type: 'note',
        spec_version: '2.1',
        id: generateSTIXId('note', event.flag.id),
        abstract: `Internal evidence: ${event.flag.code} fired in session ${event.session_id}`,
        content: `Flag ${event.flag.code} (level ${event.flag.level ?? 'n/a'}) fired at node ${event.context.node_id} on skin ${event.context.skin}. This is not an indicator.`,
        object_marking_refs: ['https://inlinelisting.opencti.io/marking/definition/open-sources'],
      },
    ],
  };
};

export const createSTIXBundle = (event: SessionEvent, objects: unknown[]): STIXBundle => ({
  type: 'bundle',
  id: generateSTIXId('bundle', event.session_id),
  objects: [sessionToIncident(event), ...objects],
});

export const eventToStixBundle = (event: Event): STIXBundle =>
  event.type === 'session.upsert' ? sessionToStixBundle(event) : flagToStixBundle(event);
