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

// Logging system tests: the application logger must be internal-only and
// resilient. The attacker-facing surface must never expose it.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import { AppLogger, type LogLevel } from '../src/logging/applog';
import { normalizeEvent, projectAttackerActivity, EVENT_SCHEMA_VERSION } from '../src/logging/eventlog';
import { createAttackerActivitySink } from '../src/logging/sinks';
import type { EventSinkLike } from '../src/logging/sinks';
import type { Event, SessionEvent, FlagEvent } from '../src/types/events';
import { createSessionEvent, createFlagEvent } from '../src/types/events';
import { StorageIndexer, createStorage } from '../src/storage/indexer';

const tmpRoot = path.join(os.tmpdir(), 'vaivar-logging-test');
let runDir = '';
let logFile = '';
let storage: StorageIndexer;

beforeEach(() => {
  runDir = path.join(tmpRoot, `run-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  fs.mkdirSync(runDir, { recursive: true });
  logFile = path.join(runDir, 'app.log');
  storage = createStorage(path.join(runDir, 'db.sqlite'));
});

afterEach(async () => {
  await storage.close().catch(() => undefined);
  try { fs.rmSync(runDir, { recursive: true, force: true }); } catch {}
});

describe('AppLogger resilience and structure', () => {
  test('writes valid JSON-lines to the configured path', () => {
    const logger = new AppLogger({ path: logFile, minLevel: 'debug', flushBytes: 1 });
    logger.info('hello', { actor: 'tester' });
    logger.error('oops');
    logger.shutdown();

    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
    expect(lines.length).toBe(2);
    const parsed = lines.map((l) => JSON.parse(l)) as Array<{ ts: string; level: LogLevel; msg: string; context?: Record<string, unknown> }>;
    expect(parsed[0].level).toBe('info');
    expect(parsed[0].context?.actor).toBe('tester');
    expect(parsed[1].level).toBe('error');
  });

  test('does not throw when the log file handle is removed mid-write', () => {
    const logger = new AppLogger({ path: logFile, minLevel: 'debug', flushBytes: 1 });
    logger.info('initial');
    logger.shutdown();
    fs.unlinkSync(logFile); // remove the file
    expect(() => logger.info('should not throw')).not.toThrow();
    expect(() => logger.shutdown()).not.toThrow();
  });

  test('rotation keeps the latest file and drops oldest after maxFiles', () => {
    const p = path.join(runDir, 'rotate.log');
    const logger = new AppLogger({ path: p, maxBytes: 1, maxFiles: 2, flushBytes: 1, minLevel: 'debug' });
    logger.info('a');
    logger.maybeRotate();
    logger.info('b');
    logger.maybeRotate();
    logger.info('c'); // re-create the active file after the last rotation
    logger.shutdown();

    const current = fs.readFileSync(p, 'utf8');
    const rotated1 = path.join(p + '.1');
    const rotated2 = path.join(p + '.2');
    const rotated3 = path.join(p + '.3');
    expect(fs.existsSync(rotated1)).toBe(true);
    expect(fs.existsSync(rotated2)).toBe(true);
    expect(fs.existsSync(rotated3)).toBe(false);
    expect(current.length).toBeGreaterThan(0);
    expect(JSON.parse(current).msg).toContain('c');
    expect(JSON.parse(fs.readFileSync(rotated1, 'utf8')).msg).toContain('b');
  });
});

describe('Normalize event schema', () => {
  test('session.upsert normalizes to envelope v2', () => {
    const event = createSessionEvent({
      sessionId: 'sid',
      seedId: 'secret',
      src: { ip: '1.2.3.4', userAgent: 'bot', headersInteresting: {} },
      agent: { class: 'scanner', tooling: [], confidence: 0.9 },
      progress: { level_max: 3, levels_closed: [1, 2, 3], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 100, requests: 5, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 2 },
      scores: { capability: 20, intent: 30 },
      skins: ['http'],
      flagsFired: ['FLAG_LEVEL'],
      severityHint: 'low',
    });
    const env = normalizeEvent(event, { traceId: 'trace' });
    expect(env.spec).toBe('vaivar.event.v2');
    expect(env.schema_version).toBe(EVENT_SCHEMA_VERSION);
    expect(env.category).toBe('session');
    expect(env.target.session_id).toBe('sid');
    expect(env.redaction).toBe('attacker');
    const payload = env.payload as Record<string, unknown>;
    expect(payload.seed_id).toBe('secret');
  });

  test('flag.hit normalizes cleanly', () => {
    const event = createFlagEvent({
      sessionId: 's1',
      code: 'FLAG_LEVEL',
      level: 2,
      flagId: 'fid',
      skin: 'wiki',
      nodeId: 'n1',
      hint: 'L2',
    });
    const env = normalizeEvent(event);
    expect(env.category).toBe('flag');
    expect((env.payload.flag as Record<string, unknown>).code).toBe('FLAG_LEVEL');
  });

  test('unknown events fallback to operator redaction', () => {
    const raw = { foo: true } as unknown as Event;
    const env = normalizeEvent(raw);
    expect(env.category).toBe('system');
    expect(env.redaction).toBe('operator');
  });
});

describe('Project attacker activity strips secrets', () => {
  test('does not leak seed_id, raw flag id, or internal hints', () => {
    const envelope = normalizeEvent(
      createSessionEvent({
        sessionId: 's1',
        seedId: 'a1b2c3d4e5f6',
        src: { ip: '1.2.3.4', userAgent: 'curl/7', headersInteresting: {} },
        agent: { class: 'scanner', tooling: [], confidence: 0.5 },
        progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
        intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 },
        scores: { capability: 0, intent: 0 },
        skins: [],
        flagsFired: [],
        severityHint: 'info',
      }),
      { source: { ip: '1.2.3.4', user_agent: 'curl/7', path: '/' } }
    );
    const rec = projectAttackerActivity(envelope, { class: 'scanner', confidence: 0.5, tools: [] });
    expect(rec.ip).toBe('1.2.3.4');
    expect(rec.level_max).toBe(0);
    expect(rec.classification).toBe('scanner');
    expect(rec.user_agent).toBe('curl/7');
  });
});

describe('Attacker activity sink persistence', () => {
  let sink: EventSinkLike;
  beforeEach(async () => {
    await storage.init();
    sink = createAttackerActivitySink(storage);
  });

  test('only accepts session and flag events', async () => {
    expect(sink.accepts({ spec: 'vaivar.event.v1', type: 'session.upsert', ts: new Date().toISOString(), session_id: 's', seed_id: 'x', src: { ip: null, userAgent: '', headersInteresting: {} }, agent: { class: 'unknown', tooling: [], confidence: 0 }, progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false }, intent: { dwell_seconds: 0, requests: 0, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 }, scores: { capability: 0, intent: 0 }, skins: [], flags_fired: [], severity_hint: 'info' } as SessionEvent)).toBe(true);
    expect(sink.accepts({ spec: 'vaivar.event.v1', type: 'flag.hit', ts: new Date().toISOString(), session_id: 's', flag: { code: 'FLAG_LEVEL', level: 1, id: 'f' }, context: { skin: 'wiki', node_id: 'n', hint: 'x' } } as FlagEvent)).toBe(true);
    // A non-event should not be accepted (fallback type check).
    expect(sink.accepts({ foo: 'bar' } as unknown as Event)).toBe(false);
  });

  test('persists without seed_id or flag code leaking into fields meant for operators', async () => {
    const event: SessionEvent = createSessionEvent({
      sessionId: 'atker',
      seedId: 'SECRET',
      src: { ip: '5.5.5.5', userAgent: 'bot', headersInteresting: {} },
      agent: { class: 'scanner', tooling: ['curl'], confidence: 0.9 },
      progress: { level_max: 2, levels_closed: [1, 2], win_isolated: false, meta_detect: true },
      intent: { dwell_seconds: 20, requests: 10, retries: 1, returning_days: 0, bytes_read: 500, nodes_visited: 5 },
      scores: { capability: 35, intent: 20 },
      skins: ['http'],
      flagsFired: ['FLAG_LEVEL'],
      severityHint: 'medium',
    });
    await sink.write(event);
    const rows = await storage.listAttackerActivity('atker');
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.event_type).toBe('session.upsert');
    expect(r.ip).toBe('5.5.5.5');
    expect(r.classification).toBe('scanner');
    expect(r.meta_detect).toBe(true);
    expect(JSON.parse(r.payload_json)).not.toHaveProperty('seed_id');
    expect(JSON.parse(r.payload_json)).not.toHaveProperty('flag');
  });
});
