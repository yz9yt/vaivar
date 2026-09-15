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

// Seed derivation (versioned seed contract).
// seed = HMAC-SHA-256(master_secret,
//                    version || session_id || attacker_fingerprint || challenge_generation)
//
// Domain separation: every downstream call that needs its own pseudo-random
// domain derives it via derive(seed, domain, logicalId). No Math.random or
// wall-clock ever influences reproducible world content.

import { createHmac, createHash } from 'node:crypto';

/** Canonical serialization that avoids ambiguity of concatenated fields. */
export const canonicalize = (parts: readonly (string | number)[]): string => {
  let out = '';
  for (const p of parts) {
    const s = String(p);
    out += `${s.length}:${s}`;
  }
  return out;
};

/** HMAC-SHA-256 hex digest of the canonicalized parts, keyed by secret. */
export const hmac = (secret: string, parts: readonly (string | number)[]): string =>
  createHmac('sha256', secret).update(canonicalize(parts)).digest('hex');

/** SHA-256 hex of the canonicalized parts (unsalted; used for fingerprints). */
export const digest = (parts: readonly (string | number)[]): string =>
  createHash('sha256').update(canonicalize(parts)).digest('hex');

/** Versioned + domain-separated per-session seed as defined by the versioned seed contract. */
export const deriveSeed = (
  masterSecret: string,
  version: string,
  sessionId: string,
  attackerFingerprint: string,
  challengeGeneration: number
): string =>
  hmac(masterSecret, [version, sessionId, attackerFingerprint, String(challengeGeneration)]);

/**
 * Derive a value in a specific domain from a root seed. Namespaced so the
 * same logical id maps to different values across domains (routes, facts,
 * recipes, skins...). Returns a hex digest up to `nBytes` (default 16).
 */
export const derive = (seed: string, domain: string, logicalId: string | number, nBytes = 16): string =>
  createHmac('sha256', seed).update(canonicalize([domain, logicalId])).digest('hex').slice(0, nBytes * 2);

/** Weighted deterministic choice: weights need not sum to 1; normalized internally. */
export const weightedPick = (
  seed: string,
  domain: string,
  logicalId: string | number,
  items: readonly { weight: number; value: unknown }[]
): { value: unknown; index: number } => {
  const hash16 = derive(seed, `${domain}|wsel`, logicalId, 16);
  const total = items.reduce((acc, it) => acc + Math.max(0, it.weight), 0);
  const roll = (parseInt(hash16.slice(0, 16), 16) % total) + 1;
  if (total <= 0) return { value: items[0]?.value, index: 0 };
  let acc = 0;
  for (let i = 0; i < items.length; i++) {
    acc += Math.max(0, items[i].weight);
    if (roll <= acc) return { value: items[i].value, index: i };
  }
  return { value: items[items.length - 1]?.value, index: items.length - 1 };
};

/** Deterministic shuffle (Fisher–Yates) driven by the seed. */
export const shuffle = <T>(seed: string, domain: string, arr: readonly T[]): T[] => {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = parseInt(derive(seed, `${domain}|shuffle|${i}`, 0, 16), 16) % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
};