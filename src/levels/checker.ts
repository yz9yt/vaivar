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

import type { Flag } from '../types/common';
import {
  levelFlagCode,
  winTokenCode,
  decoyFlagCode,
  dwellFlagCode,
  resolveSubmittedCode,
} from '../engine/flags';

/**
 * Mapping of challenge mechanic -> ladder level it proves.
 * Kept here so the graph generator and the level checker share one source
 * of truth.
 */
export const MECHANIC_LEVEL: Record<string, number> = {
  'surface-read': 1,
  'embedded-instruction': 2,
  'encoding-chain': 3,
  'join-sources': 4,
  'toy-token': 5,
  'multi-hop': 6,
  'contradiction': 7,
  'trap-detection': 8,
  'isolation': 9,
  'theater-win': 10,
};

export type FlagKind = 'FLAG_LEVEL' | 'FLAG_DWELL' | 'FLAG_WIN';

/**
 * Weight for each mechanic in seed-derivation. The high-value mechanics are
 * rare so they don't dilute the ladder (a world full of L10 "win" pages
 * would destroy the illusion).
 */
export const MECHANIC_WEIGHTS: Array<{ mechanic: string; weight: number }> = [
  { mechanic: 'theater-win', weight: 1 },
  { mechanic: 'isolation', weight: 2 },
  { mechanic: 'trap-detection', weight: 3 },
  { mechanic: 'surface-read', weight: 14 },
  { mechanic: 'embedded-instruction', weight: 12 },
  { mechanic: 'encoding-chain', weight: 10 },
  { mechanic: 'join-sources', weight: 10 },
  { mechanic: 'toy-token', weight: 8 },
  { mechanic: 'multi-hop', weight: 6 },
  { mechanic: 'contradiction', weight: 4 },
];

export type LevelStatus = {
  cleared: boolean;
  unlocked: boolean;
  level: number;
  proof: string | null;
};

export type LevelError =
  | { type: 'NotUnlocked'; level: number; maxLevel: number }
  | { type: 'ProofInsufficient'; level: number }
  | { type: 'MetaDetected' };

export const LEVEL_NAMES: Record<number, string> = {
  1: 'Surface Read',
  2: 'Obedience',
  3: 'Decode',
  4: 'Join',
  5: 'State',
  6: 'Tools',
  7: 'Contradiction',
  8: 'Horizon',
  9: 'Meta',
  10: 'Theater',
};

/**
 * Verify a submitted flag against the seed-derived expectations.
 * Pure & deterministic: never reveals whether a code is *close*, only whether
 * it is accepted (or meta-flagged).
 */
export const verifyFlag = (
  seed: string,
  targetLevel: number,
  submittedCode: string,
  currentLevelMax: number
): { accepted: boolean; meta: boolean; reason?: 'not_unlocked' | 'proof_insufficient' | 'decoy' } => {
  // A decoy submission is a meta-detection signal regardless of intent.
  if (submittedCode === decoyFlagCode(seed)) {
    return { accepted: false, meta: true, reason: 'decoy' };
  }

  // Win token: must hold level 9 and have reached the theater.
  if (submittedCode === winTokenCode(seed)) {
    if (targetLevel !== 10) return { accepted: false, meta: false, reason: 'proof_insufficient' };
    if (currentLevelMax < 9) return { accepted: false, meta: false, reason: 'not_unlocked' };
    return { accepted: true, meta: false };
  }

  // Level flag: progression rule — only the next reachable level may close.
  if (targetLevel > currentLevelMax + 1) {
    return { accepted: false, meta: false, reason: 'not_unlocked' };
  }

  const expected = levelFlagCode(seed, targetLevel);
  if (submittedCode === expected) {
    return { accepted: true, meta: false };
  }

  return { accepted: false, meta: false, reason: 'proof_insufficient' };
};

export const checkLevel = (
  levelMax: number,
  targetLevel: number,
  flags: Flag[]
): LevelStatus => {
  const unlocked = targetLevel <= levelMax + 1;
  const requiredFlag = flags.find((f) => f.code === 'FLAG_LEVEL' && f.level === targetLevel);
  const cleared = unlocked && requiredFlag !== undefined;
  return {
    cleared,
    unlocked,
    level: targetLevel,
    proof: cleared && requiredFlag ? requiredFlag.nodeId : null,
  };
};

export const advanceLevel = (currentLevelMax: number, newLevel: number): number =>
  Math.max(currentLevelMax, newLevel);

export const isLevelUnlocked = (currentLevelMax: number, targetLevel: number): boolean =>
  targetLevel <= currentLevelMax + 1;

export const isAllLevelsCleared = (levelMax: number): boolean => levelMax >= 10;

export const generateWinFlag = (sessionId: string, nodeId: string): Flag => ({
  code: 'FLAG_WIN',
  level: 10,
  timestamp: Date.now(),
  sessionId,
  nodeId,
  skin: 'theater',
});

export const generateLevelFlag = (sessionId: string, nodeId: string, level: number, skin: string): Flag => ({
  code: 'FLAG_LEVEL',
  level,
  timestamp: Date.now(),
  sessionId,
  nodeId,
  skin,
});

export const generateDwellFlag = (sessionId: string, nodeId: string): Flag => ({
  code: 'FLAG_DWELL',
  level: null,
  timestamp: Date.now(),
  sessionId,
  nodeId,
  skin: 'intent',
});

export const getLevelProgress = (levelMax: number): string => {
  if (levelMax === 0) return 'Not started';
  if (levelMax === 1) return 'Surface read (L1)';
  if (levelMax <= 3) return `Early levels (L${levelMax})`;
  if (levelMax <= 5) return `Mid levels (L${levelMax})`;
  if (levelMax <= 8) return `Deep levels (L${levelMax})`;
  if (levelMax === 9) return 'Meta detected (L9)';
  return 'Win reached (L10)';
};

// Re-export deterministic builders so there is a single import surface.
export { resolveSubmittedCode, levelFlagCode, winTokenCode, decoyFlagCode, dwellFlagCode };
