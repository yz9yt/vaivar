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

export interface SessionEvent {
  readonly spec: 'vaivar.event.v1';
  readonly type: 'session.upsert';
  readonly ts: string;
  readonly session_id: string;
  readonly seed_id: string;
  /** Deployment site identifier (multi-sede). Stamped by Edge on forward. */
  readonly site_id?: string;
  readonly src: SrcInfo;
  readonly agent: AgentInfo;
  readonly progress: ProgressInfo;
  readonly intent: IntentInfo;
  readonly scores: ScoreInfo;
  readonly skins: string[];
  readonly flags_fired: string[];
  readonly severity_hint: Severity;
}

export interface FlagEvent {
  readonly spec: 'vaivar.event.v1';
  readonly type: 'flag.hit';
  readonly ts: string;
  readonly session_id: string;
  /** Deployment site identifier (multi-sede). Stamped by Edge on forward. */
  readonly site_id?: string;
  readonly flag: {
    readonly code: 'FLAG_LEVEL' | 'FLAG_DWELL' | 'FLAG_WIN';
    readonly level: number | null;
    readonly id: string;
  };
  readonly context: {
    readonly skin: string;
    readonly node_id: string;
    readonly hint: string;
  };
}

export type Event = SessionEvent | FlagEvent;

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AgentClass = 'known' | 'scanner' | 'human_llm' | 'autonomous' | 'unknown';

export interface SrcInfo {
  readonly ip: string | null;
  readonly userAgent: string;
  readonly headersInteresting: Record<string, string>;
}

export interface AgentInfo {
  readonly class: AgentClass;
  readonly tooling: string[];
  readonly confidence: number;
}

export interface ProgressInfo {
  readonly level_max: number;
  readonly levels_closed: readonly number[];
  readonly win_isolated: boolean;
  readonly meta_detect: boolean;
}

export interface IntentInfo {
  readonly dwell_seconds: number;
  readonly requests: number;
  readonly retries: number;
  readonly returning_days: number;
  readonly bytes_read: number;
  readonly nodes_visited: number;
}

export interface ScoreInfo {
  readonly capability: number;
  readonly intent: number;
}

export interface SessionEventOpts {
  readonly sessionId: string;
  readonly seedId: string;
  readonly ts?: string;
  readonly src: SrcInfo;
  readonly agent: AgentInfo;
  readonly progress: ProgressInfo;
  readonly intent: IntentInfo;
  readonly scores: ScoreInfo;
  readonly skins: string[];
  readonly flagsFired: string[];
  readonly severityHint: Severity;
}

export const createSessionEvent = (opts: SessionEventOpts): SessionEvent => ({
  spec: 'vaivar.event.v1',
  type: 'session.upsert',
  ts: opts.ts || new Date().toISOString(),
  session_id: opts.sessionId,
  seed_id: opts.seedId,
  src: opts.src,
  agent: opts.agent,
  progress: opts.progress,
  intent: opts.intent,
  scores: opts.scores,
  skins: opts.skins,
  flags_fired: opts.flagsFired,
  severity_hint: opts.severityHint,
});

export interface FlagEventOpts {
  readonly sessionId: string;
  readonly ts?: string;
  readonly code: 'FLAG_LEVEL' | 'FLAG_DWELL' | 'FLAG_WIN';
  readonly level: number | null;
  readonly flagId: string;
  readonly skin: string;
  readonly nodeId: string;
  readonly hint: string;
}

export const createFlagEvent = (opts: FlagEventOpts): FlagEvent => ({
  spec: 'vaivar.event.v1',
  type: 'flag.hit',
  ts: opts.ts || new Date().toISOString(),
  session_id: opts.sessionId,
  flag: {
    code: opts.code,
    level: opts.level,
    id: opts.flagId,
  },
  context: {
    skin: opts.skin,
    node_id: opts.nodeId,
    hint: opts.hint,
  },
});

export const isSessionEvent = (e: Event): e is SessionEvent => 
  e.type === 'session.upsert';

export const isFlagEvent = (e: Event): e is FlagEvent => 
  e.type === 'flag.hit';

export const validateEvent = (e: Event): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  if (e.spec !== 'vaivar.event.v1') {
    errors.push('Invalid spec');
  }
  
  if (e.session_id.length === 0) {
    errors.push('Empty session_id');
  }
  
  if ('scores' in e) {
    if (e.scores.capability < 0 || e.scores.capability > 100) {
      errors.push('Capability out of range');
    }
    if (e.scores.intent < 0 || e.scores.intent > 100) {
      errors.push('Intent out of range');
    }
  }
  
  return { valid: errors.length === 0, errors };
};

export const foldEvents = (events: Event[]): SessionEvent | null => {
  const sessionEvents = events.filter(isSessionEvent);
  if (sessionEvents.length === 0) return null;
  
  const flagEvents = events.filter(isFlagEvent);
  const base = sessionEvents[sessionEvents.length - 1];
  
  const levelsClosed: number[] = [...base.progress.levels_closed];
  const flagsFired: string[] = [...base.flags_fired];
  
  for (const flag of flagEvents) {
    if (flag.flag.level !== null && !levelsClosed.includes(flag.flag.level)) {
      levelsClosed.push(flag.flag.level);
    }
    if (!flagsFired.includes(flag.flag.code)) {
      flagsFired.push(flag.flag.code);
    }
  }
  
  return {
    ...base,
    progress: {
      ...base.progress,
      levels_closed: levelsClosed,
      level_max: Math.max(base.progress.level_max, ...levelsClosed, 0),
      win_isolated: flagsFired.includes('FLAG_WIN'),
    },
    flags_fired: flagsFired,
  };
};