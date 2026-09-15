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

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  compareVersions,
  newerReleaseExists,
  newestStableRelease,
  formatUpdateNotice,
  createReleaseCatalog,
} from '../src/central/update-check';
import { createReleaseCatalog as createBaseCatalog } from '../src/central/releases';

describe('compareVersions', () => {
  it('orders simple versions', () => {
    expect(compareVersions('1.0.6', '1.0.7')).toBe(-1);
    expect(compareVersions('1.0.7', '1.0.6')).toBe(1);
    expect(compareVersions('1.0.6', '1.0.6')).toBe(0);
  });

  it('handles the v prefix and multi-part versions', () => {
    expect(compareVersions('v1.0.10', 'v1.0.9')).toBe(1);
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
    expect(compareVersions('1.0.1', '1.0.1.1')).toBe(-1);
  });

  it('treats pre-release suffixes as older than the bare release', () => {
    expect(compareVersions('1.0.1-beta', '1.0.1')).toBe(-1);
    expect(compareVersions('1.0.1', '1.0.1-beta')).toBe(1);
    expect(compareVersions('1.0.1-rc1', '1.0.1-rc2')).toBe(-1);
  });

  it('treats malformed input as equal (no alert)', () => {
    expect(compareVersions('garbage', '1.0.1')).toBe(0);
    expect(compareVersions('', '1.0.1')).toBe(0);
  });
});

describe('release catalog update check', () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaivar-update-check-'));
    const writeRelease = (version: string, channel: 'stable' | 'canary', createdAt: number) => {
      const artifact = `vaivar-${version}.bundle.tar.gz`;
      fs.writeFileSync(path.join(dir, artifact), Buffer.alloc(16));
      const manifest = {
        schema: 'vaivar.release.v1',
        version,
        channel,
        artifact,
        sha256: 'a'.repeat(64),
        size_bytes: 16,
        created_at_ms: createdAt,
      };
      fs.writeFileSync(path.join(dir, `release-${version}.manifest.json`), JSON.stringify(manifest));
    };
    // Newest stable is 1.0.7; a canary newer still exists but should be ignored for stable.
    writeRelease('1.0.6', 'stable', 1000);
    writeRelease('1.0.7', 'stable', 2000);
    writeRelease('1.1.0-rc1', 'canary', 3000);
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('detects a newer stable release', () => {
    const catalog = createReleaseCatalog(dir);
    expect(newestStableRelease(catalog)).toBe('1.0.7');
    expect(newerReleaseExists(catalog, '1.0.6')).toBe(true);
    expect(newerReleaseExists(catalog, '1.0.7')).toBe(false);
    expect(newerReleaseExists(catalog, '1.0.8')).toBe(false);
  });

  it('builds a friendly advisory line', () => {
    expect(formatUpdateNotice('1.0.6', '1.0.7')).toContain('a new version is available');
    expect(formatUpdateNotice('1.0.6', '1.0.7')).toContain('v1.0.7');
    expect(formatUpdateNotice('1.0.6', '1.0.7')).toContain('v1.0.6');
  });

  it('is compatible with the base catalog helper', () => {
    const catalog = createBaseCatalog(dir);
    expect(newerReleaseExists(catalog, '1.0.6')).toBe(true);
  });
});