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

// Deterministic hashing primitives (pure: same input -> same output).
// SHA-256 based so all derived content is stable across processes and replays.

import { createHash } from 'crypto';

export const sha256Hex = (input: string): string =>
  createHash('sha256').update(input).digest('hex');

/**
 * Stable 32-bit unsigned hash as a plain number in [0, 2^31).
 * Deterministic across processes (unlike the legacy additive hash).
 */
export const stableUint = (input: string): number => {
  const hex = sha256Hex(input).slice(0, 8);
  return parseInt(hex, 16) % 2147483647;
};

/**
 * Deterministic UUID-shaped identifier (UUIDv5-like) derived from a
 * namespace and a value. Same inputs always produce the same UUID, which
 * keeps STIX object identities stable across replays and restarts.
 */
export const deterministicUuid = (namespace: string, value: string): string => {
  const hex = sha256Hex(`${namespace}|${value}`);
  const chars = hex.split('');
  // version 5 (namespaced SHA) and RFC-4122 variant bits
  chars[12] = '5';
  chars[16] = '89ab'[parseInt(hex[16], 16) % 4];
  const h = chars.join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
};
