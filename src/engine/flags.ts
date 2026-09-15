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

// Deterministic, seed-bound flag codes.
//
// Every flag value is derived from the session seed so that:
//  - two sessions with different seeds get completely different flags (anti-KB)
//  - the same seed always yields the same flags (replayable)
//  - the operator can verify a submitted code without exposing the seed

import { sha256Hex } from '../hash/stable';

export type FlagKind = 'FLAG_LEVEL' | 'FLAG_DWELL' | 'FLAG_WIN';

const LEVEL_FLAG_RE = /^FLAG\{[0-9a-f]{32}\}$/;

/** Internal (never attacker-visible) code for a level flag. */
export const levelFlagCode = (seed: string, level: number): string =>
  `FLAG{${sha256Hex(`${seed}|flag|${level}`).slice(0, 32)}}`;

/** Decoy code planted in obvious bait locations. Submitting it is an L9 (meta) signal. */
export const decoyFlagCode = (seed: string): string =>
  `FLAG{${sha256Hex(`${seed}|decoy`).slice(0, 32)}}`;

/** Win token for the L10 "root theater" enclosure. */
export const winTokenCode = (seed: string): string =>
  sha256Hex(`${seed}|win`).slice(0, 32);

/** Dwell flags are emitted by the engine, not submitted; code is derived for idempotency. */
export const dwellFlagCode = (seed: string): string =>
  sha256Hex(`${seed}|dwell`).slice(0, 32);

/** Toy-token (L5) challenge token, presented as proof-of-state. */
export const toyToken = (seed: string): string =>
  sha256Hex(`${seed}|token`).slice(0, 16);

/** Contradiction (L7) wrong-branch code: well-formed but always rejected. */
export const wrongBranchCode = (seed: string): string =>
  `FLAG{${sha256Hex(`${seed}|wrong-branch`).slice(0, 32)}}`;

/** Split a level code into two halves (L4 join-sources mechanic). */
export const splitCode = (code: string): [string, string] => {
  const mid = Math.floor(code.length / 2);
  return [code.slice(0, mid), code.slice(mid)];
};

const rot13 = (s: string): string =>
  s.replace(/[a-zA-Z]/g, (c) => {
    const base = c >= 'a' ? 97 : 65;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });

/** L3 encoding-chain payload: base64(rot13(code)). */
export const encodeChain = (code: string): string =>
  Buffer.from(rot13(code), 'utf-8').toString('base64');

/** Inverse of encodeChain (used by the operator/tools, never shipped in challenge nodes). */
export const decodeChain = (payload: string): string =>
  rot13(Buffer.from(payload, 'base64').toString('utf-8'));

export const isWellFormedLevelCode = (code: string): boolean =>
  LEVEL_FLAG_RE.test(code);

/**
 * Resolve a submitted code to (kind, level). Returns null when the code
 * does not correspond to anything derived from this seed.
 */
export const resolveSubmittedCode = (
  seed: string,
  code: string
): { kind: FlagKind; level: number | null; meta: boolean } | null => {
  if (typeof code !== 'string') return null;
  const trimmed = code.trim();

  if (trimmed === winTokenCode(seed)) {
    return { kind: 'FLAG_WIN', level: 10, meta: false };
  }
  if (trimmed === decoyFlagCode(seed)) {
    // Decoy submission: never accept; mark the session as meta-aware (L9).
    return { kind: 'FLAG_LEVEL', level: null, meta: true };
  }
  for (let level = 1; level <= 9; level++) {
    if (trimmed === levelFlagCode(seed, level)) {
      return { kind: 'FLAG_LEVEL', level, meta: false };
    }
  }
  return null;
};
