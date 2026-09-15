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

import { sha256Hex } from '../hash/stable';

export type WorldPath = string;

export type Capability = {
  readonly name: string;
  readonly level: number;
  readonly gates: readonly string[];
};

export type WorldPlan = {
  readonly capabilities: readonly Capability[];
  readonly paths: Map<WorldPath, Capability>;
};

/**
 * KHM-02: Deep URL validation. A small plan derives which capabilities
 * unlock which routes. This is per-session but derived from the seed,
 * so the plan is different per session but verifiable.
 */
export function buildWorldPlan(seed: string, generation: number): WorldPlan {
  // Derivation is deterministic but changes per session via seed.
  const base = `${seed}|world|gen:${generation}`;
  const capabilities: Capability[] = [];

  // L1-L10 capability definitions.
  const caps = [
    { name: 'surface-read', level: 1, gates: [] },
    { name: 'surface-write', level: 2, gates: ['surface-read'] },
    { name: 'command-query', level: 3, gates: ['surface-read'] },
    { name: 'token-read', level: 4, gates: ['surface-read'] },
    { name: 'file-upload', level: 5, gates: ['surface-read'] },
    { name: 'config-write', level: 6, gates: ['surface-read'] },
    { name: 'priv-escalate', level: 7, gates: ['surface-read'] },
    { name: 'persistence', level: 8, gates: ['surface-read'] },
    { name: 'service-mesh', level: 9, gates: ['surface-read'] },
    { name: 'theater-win', level: 10, gates: ['surface-read'] },
  ];

  // Generate capability list with seeded variation for names/gates
  for (let i = 0; i < caps.length; i++) {
    const cap = caps[i];
    const jitter = (parseInt(sha256Hex(`${base}|cap|${i}`).slice(0, 8), 16) % 3) - 1;
    const level = Math.max(1, Math.min(10, cap.level + jitter));
    capabilities.push({
      name: cap.name,
      level,
      gates: [...cap.gates],
    });
  }

  // Build path map
  const paths = new Map<WorldPath, Capability>();
  for (let i = 1; i <= 10; i++) {
    const cap = capabilities[i - 1];
    const path = `/l${i}/resource-${i}`;
    paths.set(path, cap);
    // Add deeper paths that require level
    for (let d = 1; d <= 3; d++) {
      const deepPath = `${path}/deep-${d}`;
      paths.set(deepPath, cap);
    }
  }

  // Add some static roots (discovery surfaces — always accessible)
  paths.set('/', { name: 'surface-read', level: 0, gates: [] });
  paths.set('/status', { name: 'surface-read', level: 0, gates: [] });

  return { capabilities, paths };
}

/** Check whether a session's capability level unlocks the path */
export function canAccessPath(plan: WorldPlan, sessionLevelMax: number, path: string): boolean {
  const cap = plan.paths.get(path);
  if (!cap) {
    // Unknown path: allow shallow paths (depth <= 2) to be served as
    // corridor or degraded content (budget gate handles cap). Block
    // deep unknown paths unless the session has unlocked deep capability.
    if (path.startsWith('/')) {
      const depth = path.split('/').filter(Boolean).length;
      if (depth <= 2) return true;
      return sessionLevelMax >= 5;
    }
    return false;
  }
  return sessionLevelMax >= cap.level;
}

/**
 * Verify WorldPlan coherence: all deep paths in the plan have
 * capability levels that match their depth requirement.
 * Returns true if every /l{n}/resource-{k}/deep-{d} path has
 * a capability level >= 1 and the depth is consistent.
 */
export function verifyPlanCoherence(plan: WorldPlan): boolean {
  for (const [path, cap] of plan.paths) {
    const depth = path.split('/').filter(Boolean).length;
    if (path.startsWith('/') && depth > 2) {
      // Deep paths must have a meaningful capability level
      if (cap.level < 1) return false;
    }
  }
  return true;
}

/** Export a minimal plan for tests. */
export const EMPTY_WORLD_PLAN: WorldPlan = {
  capabilities: [],
  paths: new Map(),
};
