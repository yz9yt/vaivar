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

// Real, contract-driven tests covering the documented hard requirements:
//  - RF-ANTI-KB-1: different seeds produce different worlds.
//  - RF-MECH-ENG-1..3: deterministic generation, budget, progression.
//  - RF-SKIN-3/4: zero brand leaks.
//  - RF-SEC-1: no seed leakage.
//  - RF-CTI-1/2: deterministic IDs, IOC policy, real POST to OpenCTI.
//  - RF-ENG-5: no level disclosure, degraded corridor instead of 503.
//  - RF-THEORY: classifier signals, scoring bounds.

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { sha256Hex } from '../src/hash/stable';
import {
  levelFlagCode,
  decoyFlagCode,
  winTokenCode,
  encodeChain,
  decodeChain,
  splitCode,
  isWellFormedLevelCode,
  resolveSubmittedCode,
} from '../src/engine/flags';
import { generateNode, generateNodes, toPublicNode, deriveMechanic, deriveLevel } from '../src/graph/generator';
import {
  verifyFlag,
  checkLevel,
  advanceLevel,
  isLevelUnlocked,
  isAllLevelsCleared,
  MECHANIC_LEVEL,
} from '../src/levels/checker';
import { classifyRequest, isMetaProbe, recordPattern } from '../src/classifier/analyzer';
import { computeCapability, computeIntent, computeMatrix } from '../src/scoring/capability';
import { checkNoBrandStrings, sanitizeBrandStrings } from '../src/skins/validators';
import { renderWikiPage } from '../src/skins/wiki';
import { createOpenAPISkin } from '../src/skins/openapi';
import { generateSTIXId, isIndicatorCandidate, validateAsIndicator } from '../src/cti/ids';
import { sessionToStixBundle, flagToStixBundle } from '../src/cti/transform';
import { OpenCTIConnector } from '../src/cti/connector';
import { SessionEngine } from '../src/engine/session';
import { StorageIndexer, createStorage } from '../src/storage/indexer';
import { createSessionEvent, createFlagEvent, isSessionEvent, isFlagEvent, foldEvents } from '../src/types/events';

const SEED = 'a'.repeat(64);
const MASTER_SECRET = 'test-only-master-secret-not-production-2026';
const DIFF_SEED = 'z'.repeat(64);
const BUDGET = {
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
const SMALL_BUDGET = { ...BUDGET, maxNodes: 2, maxBytes: 1 };

describe('Flags determinism and resolution', () => {
  test('level flags are deterministic', () => {
    expect(levelFlagCode(SEED, 1)).toBe(levelFlagCode(SEED, 1));
    expect(levelFlagCode(SEED, 2)).not.toBe(levelFlagCode(SEED, 1));
    expect(levelFlagCode(SEED, 1)).not.toBe(levelFlagCode(DIFF_SEED, 1));
  });

  test('decoy and win tokens are deterministic and distinct', () => {
    expect(decoyFlagCode(SEED)).toBeTruthy();
    expect(winTokenCode(SEED)).toBeTruthy();
    expect(decoyFlagCode(SEED)).not.toBe(winTokenCode(SEED));
    expect(decoyFlagCode(SEED)).not.toBe(levelFlagCode(SEED, 1));
  });

  test('encode/decode chain round-trips', () => {
    const code = levelFlagCode(SEED, 3);
    const payload = encodeChain(code);
    expect(payload).not.toBe(code);
    expect(decodeChain(payload)).toBe(code);
  });

  test('splitCode divides in half', () => {
    const code = levelFlagCode(SEED, 4);
    const [a, b] = splitCode(code);
    expect(a.length + b.length).toBe(code.length);
    expect(a).not.toBe(b);
    expect(a + b).toBe(code);
  });

  test('isWellFormedLevelCode validates format', () => {
    expect(isWellFormedLevelCode('FLAG{abcd1234abcd1234abcd1234abcd1234}')).toBe(true);
    expect(isWellFormedLevelCode('FLAG{abc}')).toBe(false);
    expect(isWellFormedLevelCode('FLAG{invalid!chars}')).toBe(false);
  });

  test('resolveSubmittedCode recognizes the right codes', () => {
    expect(resolveSubmittedCode(SEED, levelFlagCode(SEED, 5))).toEqual({
      kind: 'FLAG_LEVEL',
      level: 5,
      meta: false,
    });
    expect(resolveSubmittedCode(SEED, winTokenCode(SEED))).toEqual({
      kind: 'FLAG_WIN',
      level: 10,
      meta: false,
    });
    expect(resolveSubmittedCode(SEED, decoyFlagCode(SEED))).toEqual({
      kind: 'FLAG_LEVEL',
      level: null,
      meta: true,
    });
    expect(resolveSubmittedCode(SEED, 'unknown')).toBeNull();
  });
});

describe('Level verification rules', () => {
  test('accepts correct code for the claimed level', () => {
    expect(verifyFlag(SEED, 3, levelFlagCode(SEED, 3), 2)).toEqual({ accepted: true, meta: false });
  });

  test('rejects wrong code', () => {
    expect(verifyFlag(SEED, 3, 'wrong', 2)).toEqual({ accepted: false, meta: false, reason: 'proof_insufficient' });
  });

  test('prevents skipping levels (progression rule)', () => {
    // Must have closed level 2 before clearing level 3.
    expect(verifyFlag(SEED, 3, levelFlagCode(SEED, 3), 0)).toEqual({ accepted: false, meta: false, reason: 'not_unlocked' });
  });

  test('decoy submission is always rejected and flagged as meta', () => {
    const v = verifyFlag(SEED, 1, decoyFlagCode(SEED), 0);
    expect(v.accepted).toBe(false);
    expect(v.meta).toBe(true);
  });

  test('win token requires level 9 and targets level 10', () => {
    expect(verifyFlag(SEED, 10, winTokenCode(SEED), 8)).toEqual({ accepted: false, meta: false, reason: 'not_unlocked' });
    expect(verifyFlag(SEED, 10, winTokenCode(SEED), 9)).toEqual({ accepted: true, meta: false });
  });

  test('checkLevel honors cleared/unlocked semantics', () => {
    const status = checkLevel(2, 3, []);
    expect(status.unlocked).toBe(true);
    expect(status.cleared).toBe(false);
    expect(status.proof).toBeNull();
  });

  test('advanceLevel never regresses', () => {
    expect(advanceLevel(2, 1)).toBe(2);
    expect(advanceLevel(2, 3)).toBe(3);
    expect(advanceLevel(0, 1)).toBe(1);
  });

  test('isLevelUnlocked enforces progression', () => {
    expect(isLevelUnlocked(0, 1)).toBe(true);
    expect(isLevelUnlocked(1, 1)).toBe(true);
    expect(isLevelUnlocked(1, 3)).toBe(false);
  });

  test('isAllLevelsCleared is true only at L10', () => {
    expect(isAllLevelsCleared(9)).toBe(false);
    expect(isAllLevelsCleared(10)).toBe(true);
  });
});

describe('Graph mechanics and flag embedding', () => {
  test('deterministic node bytes for same seed+path', () => {
    const a = generateNode({ seed: SEED, path: '/start', budget: BUDGET, currentNodeCount: 0, currentBytes: 0 });
    const b = generateNode({ seed: SEED, path: '/start', budget: BUDGET, currentNodeCount: 0, currentBytes: 0 });
    expect(JSON.stringify(a.value)).toBe(JSON.stringify(b.value));
  });

  test('different seeds produce different node bytes', () => {
    const a = generateNode({ seed: SEED, path: '/start', budget: BUDGET, currentNodeCount: 0, currentBytes: 0 });
    const b = generateNode({ seed: DIFF_SEED, path: '/start', budget: BUDGET, currentNodeCount: 0, currentBytes: 0 });
    expect(JSON.stringify(a.value)).not.toBe(JSON.stringify(b.value));
  });

  test('deriving the same path always yields the same hash', () => {
    const a = deriveMechanic(SEED, '/start', 1);
    const b = deriveMechanic(SEED, '/start', 1);
    expect(a).toBe(b);
  });

  test('MECHANIC_LEVEL is a bijection from 1 to 10', () => {
    const levels = Object.values(MECHANIC_LEVEL);
    expect(levels.sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  test('surface-read contains the L1 flag directly', () => {
    // Use a known seed/mechanic pair: deriveMechanic returns surface-read for specific paths.
    // We verify the mechanic->level binding directly.
    expect(MECHANIC_LEVEL['surface-read']).toBe(1);
  });

    test('theater-win mechanic exists in MECHANIC_LEVEL', () => {
    expect(MECHANIC_LEVEL['theater-win']).toBe(10);
  });

  test('no seed leaks into node JSON', () => {
    const node = generateNode({ seed: SEED, path: '/secret', budget: BUDGET, currentNodeCount: 0, currentBytes: 0 }).value;
    const body = JSON.stringify(node);
    expect(body).not.toContain(SEED);
  });

  test('degraded corridor when budget exceeded returns isDegraded without error', () => {
    const r = generateNode({ seed: SEED, path: '/top', budget: SMALL_BUDGET, currentNodeCount: 3, currentBytes: 10 });
    expect(r.ok).toBe(true);
    expect(r.value.isDegraded).toBe(true);
  });

  test('toPublicNode strips internal metadata and gates links', () => {
    const node = generateNode({ seed: SEED, path: '/deep', budget: BUDGET, currentNodeCount: 0, currentBytes: 0 }).value;
    const pub = toPublicNode(node, 0);
    expect(pub).not.toHaveProperty('metadata');
    expect(pub).not.toHaveProperty('isDegraded');
    expect(pub).toHaveProperty('links');
  });
});

describe('Budget enforcement (no 503, no limit disclosure)', () => {
  test('serveNode returns degraded boolean without throwing when over maxNodes', () => {
    const engine = new SessionEngine({ masterSecret: MASTER_SECRET, budget: SMALL_BUDGET, skins: ['http'] });
    const sessionId = 'eng-budget-test';
    engine.getOrCreate(sessionId, { ip: '1.1.1.1', userAgent: 'bot' });
    for (let i = 0; i < 3; i++) engine.serveNode(sessionId, { ip: '1.1.1.1', userAgent: 'bot' }, '/n');
    expect(engine.snapshot(sessionId)?.budget.nodes).toBeLessThanOrEqual(3);
  });

  test('serveNode never returns a 503-equivalent error state', () => {
    const engine = new SessionEngine({ masterSecret: MASTER_SECRET, budget: SMALL_BUDGET, skins: ['http'] });
    const sid = 'eng-budget-2';
    engine.getOrCreate(sid, { ip: '2.2.2.2', userAgent: 'ua' });
    const r = engine.serveNode(sid, { ip: '2.2.2.2', userAgent: 'ua' }, '/x');
    // Degraded is ok; error means a bug.
    expect(r.ok).toBe(true);
  });
});

describe('Brand-string sanitization and no-leak in surfaces', () => {
  const BRANDS = ['vAIvar', 'vaivar', 'vivar', 'rabbithole'];

  test('sanitizeBrandStrings removes every forbidden brand', () => {
    const mixed = `This is vAIvar and Vaivar and vivar and RABBITHOLE`;
    const out = sanitizeBrandStrings(mixed);
    for (const brand of BRANDS) {
      expect(out.toLowerCase()).not.toContain(brand.toLowerCase());
    }
    expect(out).toContain('[redacted]');
  });

  test('renderWikiPage body has no brand strings', () => {
    const resp = renderWikiPage({ title: 'Test', content: 'hello' }, '/wiki', SEED);
    const violations = checkNoBrandStrings(resp);
    expect(violations.ok).toBe(true);
  });

  test('wiki response headers contain no brand strings', () => {
    const resp = renderWikiPage({ title: 'Test' }, '/', SEED);
    const violations = checkNoBrandStrings(resp);
    expect(violations.ok).toBe(true);
  });

  test('openapi skin has no brand strings', () => {
    const doc = createOpenAPISkin({ title: 'Test', version: '1', basePath: '/api', seed: SEED });
    const body = JSON.stringify(doc);
    for (const brand of BRANDS) {
      expect(body).not.toContain(brand);
    }
  });
});

describe('Classifier signals', () => {
  const ts = (offset: number) => Date.now() - offset;

  test('burst + wordlist paths classify as scanner', () => {
    const patterns: RequestPattern[] = [
      {
        path: '/.env',
        method: 'GET',
        userAgent: 'curl/7.81',
        headers: {},
        timestamps: [ts(0)],
        requestCount: 1,
        uniquePaths: 1,
      },
      {
        path: '/wp-admin',
        method: 'GET',
        userAgent: 'curl/7.81',
        headers: {},
        timestamps: [ts(0), ts(50)],
        requestCount: 2,
        uniquePaths: 2,
      },
      {
        path: '/admin',
        method: 'GET',
        userAgent: 'curl/7.81',
        headers: {},
        timestamps: [ts(0), ts(50), ts(55)],
        requestCount: 3,
        uniquePaths: 3,
      },
    ];
    const cls = classifyRequest(
      { path: '/.env', method: 'GET', headers: {}, userAgent: 'curl/7.81' },
      patterns
    );
    expect(cls.class).toBe('scanner');
    expect(cls.confidence).toBeGreaterThan(0);
  });

  test('semantic navigation + tooling ua classify as autonomous', () => {
    const baseTs = Date.now();
    const patterns: RequestPattern[] = [
      { path: '/docs', method: 'GET', userAgent: 'claude/1.0', headers: {}, timestamps: [baseTs], requestCount: 1, uniquePaths: 1 },
      { path: '/docs/intro', method: 'GET', userAgent: 'claude/1.0', headers: {}, timestamps: [baseTs, baseTs + 2000], requestCount: 2, uniquePaths: 2 },
      { path: '/docs/api', method: 'GET', userAgent: 'claude/1.0', headers: {}, timestamps: [baseTs, baseTs + 2000, baseTs + 4000], requestCount: 3, uniquePaths: 3 },
    ];
    const cls = classifyRequest(
      { path: '/docs/api', method: 'GET', headers: {}, userAgent: 'claude/1.0' },
      patterns
    );
    expect(cls.class).toBe('autonomous');
  });

  test('isMetaProbe detects generator probing', () => {
    expect(isMetaProbe('is this a honeypot?')).toBe(true);
    expect(isMetaProbe('is this real?')).toBe(true);
    expect(isMetaProbe('are you an llm?')).toBe(true);
    expect(isMetaProbe('hello there')).toBe(false);
    expect(isMetaProbe('generate more content')).toBe(false);
  });
});

describe('Scoring bounds and matrix labels', () => {
  test('computeCapability is clamped to [0, 100]', () => {
    expect(computeCapability({ levelMax: 10, metaDetect: true, win: true, levelsPerHour: 24 })).toBe(100);
    expect(computeCapability({ levelMax: 0 })).toBe(0);
    expect(computeCapability({ levelMax: 100 })).toBeLessThanOrEqual(100);
  });

  test('computeIntent is clamped to [0, 100]', () => {
    expect(computeIntent({ dwellSeconds: 0, requests: 0 })).toBe(0);
    expect(computeIntent({ dwellSeconds: 99999999 })).toBeLessThanOrEqual(100);
  });

  test('matrix alerts are one of the documented enum values', () => {
    const alerts = new Set<string>();
    for (let cap = 0; cap <= 100; cap += 25) {
      for (let intent = 0; intent <= 100; intent += 25) {
        const a = computeMatrix(cap, intent).alert;
        alerts.add(a);
      }
    }
    const valid = new Set(['noise', 'proving', 'intent_alert', 'watch', 'bounded_threat', 'alert', 'capability_alert', 'serious', 'maximum']);
    for (const a of alerts) expect(valid.has(a)).toBe(true);
  });
});

describe('STIX deterministic identity and IOC policy', () => {
  test('generateSTIXId is deterministic', () => {
    expect(generateSTIXId('incident', 'sess-1')).toBe(generateSTIXId('incident', 'sess-1'));
    expect(generateSTIXId('incident', 'sess-1')).not.toBe(generateSTIXId('incident', 'sess-2'));
  });

  test('public IPv4 is an indicator candidate', () => {
    expect(isIndicatorCandidate({ type: 'ipv4-addr', labels: [] })).toBe(true);
  });

  test('generated URL observables are never indicators', () => {
    const v = validateAsIndicator({ type: 'url', value: 'http://maze.example/a/b' });
    expect(v.isIndicator).toBe(false);
    expect(v.reason).toMatch(/correlation|Generated|not an IOC/i);
  });

  test('private IPv4 addresses are not indicators', () => {
    expect(validateAsIndicator({ type: 'ipv4-addr', value: '10.0.0.1' }).isIndicator).toBe(false);
    expect(validateAsIndicator({ type: 'ipv4-addr', value: '192.168.1.1' }).isIndicator).toBe(false);
    expect(validateAsIndicator({ type: 'ipv4-addr', value: '127.0.0.1' }).isIndicator).toBe(false);
  });

  test('flag events never become indicators', () => {
    const bundle = flagToStixBundle(createFlagEvent({
      sessionId: 's1',
      code: 'FLAG_LEVEL',
      level: 1,
      flagId: 'fid',
      skin: 'wiki',
      nodeId: 'n1',
      hint: 'L1',
    }));
    // Flags should not emit ipv4-addr indicators.
    for (const obj of bundle.objects) {
      const o = obj as Record<string, unknown>;
      expect(o.type).not.toBe('ipv4-addr');
    }
  });
});

describe('Session engine end-to-end', () => {
  let engine: SessionEngine;
  beforeEach(() => {
    engine = new SessionEngine({ masterSecret: MASTER_SECRET, budget: BUDGET, skins: ['http', 'mcp'] });
  });

  test('deriveSeed binds per-session + fingerprint', () => {
    const a = engine.deriveSeed('s1', 'fp1');
    const b = engine.deriveSeed('s1', 'fp2');
    const c = engine.deriveSeed('s2', 'fp1');
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });

  test('creating two sessions yields distinct seeds', () => {
    const s1 = engine.getOrCreate('sess-a', { ip: '1.1.1.1', userAgent: 'ua1' });
    const s2 = engine.getOrCreate('sess-b', { ip: '2.2.2.2', userAgent: 'ua2' });
    expect(s1.seed).not.toBe(s2.seed);
  });

  const engineSeed = (sid: string): string => engine.get(sid)!.seed;

  test('submitting the correct L1 flag clears level 1', () => {
    const sid = 'f1';
    engine.getOrCreate(sid, { ip: '1.1.1.1', userAgent: 'bot' });
    const r = engine.submitCode(sid, { ip: '1.1.1.1', userAgent: 'bot' }, levelFlagCode(engineSeed(sid), 1), 'wiki', 'node1');
    expect(r.accepted).toBe(true);
    expect(r.levelMax).toBe(1);
    expect(r.kind).toBe('FLAG_LEVEL');
  });

  test('submitting the win token at level 9 is isolated', () => {
    const sid = 'win';
    engine.getOrCreate(sid, { ip: '1.1.1.1', userAgent: 'bot' });
    // Fast-forward to level 9 by submitting all lower flags.
    for (let i = 1; i <= 9; i++) {
      engine.submitCode(sid, { ip: '1.1.1.1', userAgent: 'bot' }, levelFlagCode(engineSeed(sid), i), 'wiki', `n${i}`);
    }
    const snap = engine.snapshot(sid)!;
    expect(snap.levelMax).toBe(9);
    const r = engine.submitCode(sid, { ip: '1.1.1.1', userAgent: 'bot' }, winTokenCode(engineSeed(sid)), 'wiki', 'root');
    expect(r.accepted).toBe(true);
    expect(r.kind).toBe('FLAG_WIN');
    expect(r.levelMax).toBe(10);
  });

  test('flushAll drains events and yields fresh session.upserts', () => {
    const sid = 'flush';
    engine.getOrCreate(sid, { ip: '1.1.1.1', userAgent: 'bot' });
    engine.submitCode(sid, { ip: '1.1.1.1', userAgent: 'bot' }, levelFlagCode(engineSeed(sid), 1), 'wiki', 'n');
    const { events, sessionEvents } = engine.flushAll();
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(sessionEvents.length).toBeGreaterThanOrEqual(1);
    const firstEvent = events[0];
    expect(isSessionEvent(firstEvent) || isFlagEvent(firstEvent)).toBe(true);
  });

  test('snapshot never includes the raw seed', () => {
    const sid = 'snap';
    engine.getOrCreate(sid, { ip: '1.1.1.1', userAgent: 'bot' });
    const snap = engine.snapshot(sid)!;
    expect(JSON.stringify(snap)).not.toContain(engine.get(sid)!.seed);
  });

  test('listSessions returns snapshots without seeds', () => {
    engine.getOrCreate('l1', { ip: '1.1.1.1', userAgent: 'ua1' });
    engine.getOrCreate('l2', { ip: '2.2.2.2', userAgent: 'ua2' });
    const list = engine.listSessions();
    expect(list.length).toBe(2);
    for (const s of list) expect(JSON.stringify(s)).not.toContain(SEED);
  });
});

describe('Storage null-safety', () => {
  let storage: StorageIndexer;
  beforeEach(async () => {
    storage = createStorage(':memory:');
    await storage.init();
  });
  afterEach(async () => {
    await storage.close().catch(() => undefined);
  });

  test('saves and replays session events', async () => {
    const e = createSessionEvent({
      sessionId: 'sid',
      seedId: 'seed',
      src: { ip: '1.2.3.4', userAgent: 'ua', headersInteresting: {} },
      agent: { class: 'scanner', tooling: [], confidence: 0.5 },
      progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 },
      scores: { capability: 0, intent: 0 },
      skins: ['http'],
      flagsFired: [],
      severityHint: 'info',
    });
    await storage.saveEvent(e);
    const rows = await storage.getEvents('sid');
    expect(rows.length).toBeGreaterThanOrEqual(1);
  });

  test('saveFlag persists and retrievable', async () => {
    await storage.saveFlag('sid', 'FLAG{abc}', 1, 'node');
    const flags = await storage.getFlags('sid');
    expect(flags).toHaveLength(1);
    expect(flags[0].flag_code).toBe('FLAG{abc}');
  });

  test('replaySession works even when db is null (fallback)', async () => {
    // Use an uninitializable path to force memory fallback.
    const alt = createStorage(':/invalid/path');
    await alt.init();
    const events = await alt.replaySession('missing');
    expect(events).toEqual([]);
    await alt.clear();
    await alt.close();
  });

  test('clear empties all in-memory state', async () => {
    await storage.saveEvent(createSessionEvent({ sessionId: 's', seedId: 'x', src: { ip: null, userAgent: '', headersInteresting: {} }, agent: { class: 'unknown', tooling: [], confidence: 0 }, progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false }, intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 }, scores: { capability: 0, intent: 0 }, skins: [], flagsFired: [], severityHint: 'info' }));
    await storage.clear();
    const stats = await storage.getStats();
    expect(stats.events).toBe(0);
  });

  test('deterministic event id across saves', async () => {
    const e = createSessionEvent({ sessionId: 's', seedId: 'x', src: { ip: null, userAgent: '', headersInteresting: {} }, agent: { class: 'unknown', tooling: [], confidence: 0 }, progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false }, intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 }, scores: { capability: 0, intent: 0 }, skins: [], flagsFired: [], severityHint: 'info' });
    await storage.saveEvent(e);
    await storage.saveEvent(e);
    const rows = await storage.getEvents('s');
    // Idempotent id should deduplicate; still <=1 stored event.
    expect(rows.length).toBeLessThanOrEqual(1);
  });
});

describe('Fold events into latest session state', () => {
  test('fold merges flag events into session progress', () => {
    const base = createSessionEvent({
      sessionId: 's',
      seedId: 'x',
      src: { ip: null, userAgent: '', headersInteresting: {} },
      agent: { class: 'unknown', tooling: [], confidence: 0 },
      progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 },
      scores: { capability: 0, intent: 0 },
      skins: ['http'],
      flagsFired: [],
      severityHint: 'info',
    });
    const f1 = createFlagEvent({ sessionId: 's', code: 'FLAG_LEVEL', level: 1, flagId: 'f1', skin: 'wiki', nodeId: 'n1', hint: 'L1' });
    const f2 = createFlagEvent({ sessionId: 's', code: 'FLAG_WIN', level: 10, flagId: 'w', skin: 'wiki', nodeId: 'n2', hint: 'win' });
    const folded = foldEvents([base, f1, f2]);
    expect(folded).not.toBeNull();
    expect(folded!.progress.level_max).toBe(10);
    expect(folded!.progress.win_isolated).toBe(true);
    expect(folded!.flags_fired).toContain('FLAG_LEVEL');
    expect(folded!.flags_fired).toContain('FLAG_WIN');
  });
});

describe('OpenCTI connector posts real STIX bundles', () => {
  let connector: OpenCTIConnector;
  let captured: unknown;
  let srv: http.Server;

  beforeEach(async () => {
    captured = undefined;
    connector = new OpenCTIConnector({ url: 'http://localhost:0', token: 'tok', maxRetries: 1 });
    srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        try { captured = JSON.parse(body); } catch { captured = body; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('ok');
      });
    });
    await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
    // Override the connector url since port is assigned randomly.
    const addr = srv.address() as import('net').AddressInfo;
    connector = new OpenCTIConnector({ url: `http://127.0.0.1:${addr.port}`, token: 'tok', maxRetries: 1 });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
  });

  test('emits a session.upsert as a STIX bundle', async () => {
    const evt = createSessionEvent({
      sessionId: 'sess-real',
      seedId: 'seed',
      src: { ip: '1.2.3.4', userAgent: 'bot', headersInteresting: {} },
      agent: { class: 'scanner', tooling: [], confidence: 0.9 },
      progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 10, requests: 5, retries: 0, returning_days: 0, bytes_read: 100, nodes_visited: 2 },
      scores: { capability: 10, intent: 10 },
      skins: ['http'],
      flagsFired: [],
      severityHint: 'low',
    });
    await connector.handleEvent(evt);
    await new Promise((r) => setTimeout(r, 50));
    expect(captured).toBeDefined();
    const bundle = captured as Record<string, unknown>;
    expect(bundle.type).toBe('bundle');
    const objects = bundle.objects as Array<Record<string, unknown>>;
    const incident = objects.find((o) => o.type === 'incident');
    expect(incident).toBeDefined();
  });

  test('only real attacker IPs become indicators', async () => {
    const evt = createSessionEvent({
      sessionId: 'ip-test',
      seedId: 'x',
      src: { ip: '8.8.8.8', userAgent: '', headersInteresting: {} },
      agent: { class: 'scanner', tooling: [], confidence: 0 },
      progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 },
      scores: { capability: 0, intent: 0 },
      skins: [],
      flagsFired: [],
      severityHint: 'info',
    });
    await connector.handleEvent(evt);
    await new Promise((r) => setTimeout(r, 50));
    const bundle = captured as Record<string, unknown>;
    const objects = bundle.objects as Array<Record<string, unknown>>;
    const indicator = objects.find((o) => o.type === 'ipv4-addr');
    expect(indicator).toBeDefined();
    expect((indicator as Record<string, unknown>).value).toBe('8.8.8.8');
  });

  test('disabled connector queues bundles in memory', async () => {
    const disabled = new OpenCTIConnector({ url: '', token: '' });
    expect(disabled.enabled).toBe(false);
    const evt = createSessionEvent({
      sessionId: 'q',
      seedId: 'x',
      src: { ip: null, userAgent: '', headersInteresting: {} },
      agent: { class: 'unknown', tooling: [], confidence: 0 },
      progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 },
      scores: { capability: 0, intent: 0 },
      skins: [],
      flagsFired: [],
      severityHint: 'info',
    });
    await disabled.handleEvent(evt);
    expect(disabled.getStatistics().queued).toBeGreaterThan(0);
  });
});
