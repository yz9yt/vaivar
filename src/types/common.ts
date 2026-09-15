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

// Core domain primitives shared across layers. Event/session types live in
// types/events.ts and are re-exported here only for backward compatibility.

export type {
  SessionEvent,
  FlagEvent,
  Event,
  Severity,
  AgentClass,
  SrcInfo,
  AgentInfo,
  ProgressInfo,
  IntentInfo,
  ScoreInfo,
} from './events';
export { createSessionEvent, createFlagEvent, validateEvent, foldEvents } from './events';

export type NodeType = 'docs' | 'api' | 'ticket' | 'commit' | 'vault' | 'panel' | 'isolation' | 'degraded';

export interface Flag {
  readonly code: 'FLAG_LEVEL' | 'FLAG_DWELL' | 'FLAG_WIN';
  readonly level: number | null;
  readonly timestamp: number;
  readonly sessionId: string;
  readonly nodeId: string;
  readonly skin: string;
}

export interface BudgetState {
  readonly nodes: number;
  readonly bytes: number;
  readonly requests: number;
  readonly cpuMs: number;
}

export interface BudgetLimits {
  readonly maxNodes: number;
  readonly maxBytes: number;
  readonly maxRequests: number;
  readonly maxCpuMs: number;
  readonly expiryHours: number;
  readonly nodeIncrement: number;
  readonly byteIncrement: number;
  readonly requestIncrement: number;
  readonly cpuIncrement: number;
}

export const DEFAULT_BUDGET: BudgetLimits = {
  maxNodes: 500,
  maxBytes: 50 * 1024 * 1024,
  maxRequests: 10000,
  maxCpuMs: 10000,
  expiryHours: 48,
  nodeIncrement: 1,
  byteIncrement: 1000,
  requestIncrement: 1,
  cpuIncrement: 1,
};

export interface NodeLink {
  readonly target: string;
  readonly path: string;
  readonly type: 'page' | 'api' | 'commit' | 'ticket';
  readonly condition?: string;
  readonly visible: boolean;
}

export interface Node {
  readonly id: string;
  readonly type: NodeType;
  readonly path: string;
  readonly content: unknown;
  readonly links: readonly NodeLink[];
  readonly level: number | null;
  readonly isDegraded: boolean;
  readonly metadata: NodeMetadata;
}

export interface NodeMetadata {
  readonly createdAt: number;
  readonly size: number;
  readonly isSecret: boolean;
  readonly isTrap: boolean;
}

export interface Response {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

// Response with randomized signatures for anti-fingerprinting
export interface SignedResponse extends Response {
  readonly signature: string;
  readonly server: string;
}

/** Opaque brand for the session seed (lives only on the defender side). */
export type Seed = string & { readonly __brand: 'Seed' };

/** Opaque brand for skin identifiers. */
export type Skin = string & { readonly __brand: 'Skin' };

export interface SignatureConfig {
  readonly serverHeaders: string[];
  readonly contentTypeVariants: string[];
}

export const DEFAULT_SIGNATURES: SignatureConfig = {
  serverHeaders: ['nginx', 'apache', 'caddy', 'cloudflare', 'vercel'],
  contentTypeVariants: ['application/json', 'text/json', 'application/vnd.api+json'],
};
