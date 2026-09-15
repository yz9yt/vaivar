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

// Version update check for the central plane.
//
// Reuses the local release catalog (releases.ts) as the source of truth so
// the check works without Internet access. When a newer stable release
// manifest exists, the caller logs a non-blocking advisory line.

import { createReleaseCatalog, type ReleaseCatalog } from './releases';

/** Split a version into a numeric core and an optional pre-release suffix. */
const parseVersion = (raw: string): { nums: number[]; pre: string } | null => {
  const clean = raw.replace(/^v/i, '').trim();
  const m = clean.match(/^(\d+(?:\.\d+)*)(?:[-+](.*))?$/);
  if (!m) return null;
  return {
    nums: m[1].split('.').map((n) => parseInt(n, 10) || 0),
    pre: (m[2] ?? '').toLowerCase(),
  };
};

const compareNums = (a: number[], b: number[]): -1 | 0 | 1 => {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
};

/**
 * Return -1 when `a < b`, 0 when equal, 1 when `a > b`.
 * Pre-release suffix sorts before the same numeric release.
 * Malformed input is the "equal" case (no alert).
 */
export const compareVersions = (a: string, b: string): -1 | 0 | 1 => {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return 0;
  const nums = compareNums(pa.nums, pb.nums);
  if (nums !== 0) return nums;
  if (pa.pre === pb.pre) return 0;
  // A release with a suffix is older than the bare release ("1.0.1-beta" < "1.0.1").
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre < pb.pre ? -1 : 1;
};

/** Newest stable release version in the catalog, or null when none/empty. */
export const newestStableRelease = (catalog: ReleaseCatalog): string | null => {
  const stable = catalog.list('stable');
  if (stable.length === 0) return null;
  return stable[0].version;
};

/** True when the newest stable release is newer than the running version. */
export const newerReleaseExists = (catalog: ReleaseCatalog, current: string): boolean => {
  const latest = newestStableRelease(catalog);
  if (!latest) return false;
  return compareVersions(latest, current) > 0;
};

/** Build the advisory log line (pure string, no side effects). */
export const formatUpdateNotice = (current: string, latest: string): string =>
  `[vaivar] a new version is available: v${latest} (you are on v${current}). See docs/RELEASES-AND-BOOTSTRAP.md`;

export { createReleaseCatalog };
export type { ReleaseCatalog };