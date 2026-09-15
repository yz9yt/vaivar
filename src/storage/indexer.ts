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

// vAIvar Storage Indexer - SQLite backend with in-memory fallback.
// Persistent storage for sessions, events, and flags. Event ids are
// deterministic (SHA-256 of payload) so replays do not duplicate rows.

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import type { SessionRecord, FlagRecord, AttackerActivityRecord, StorageStats, StorageConfig, CentralNodeRecord, CentralNodeCapability, CentralTemplateRecord, BootstrapTokenMetadata, ExportDeliveryRecord, IntegrationSetting, IntegrationKind, HoneypotRuntimeConfig } from './types';
import { isHoneypotProfile, normalizeHoneypotProfile } from '../node/config';
import { validateHoneypotTemplate, type HoneypotTemplate } from '../templates/types';
import type { Event } from '../types/events';
import type { EventEnvelope } from '../logging/eventlog';
import { sha256Hex } from '../hash/stable';
import { randomBytes } from 'crypto';

const RETENTION_DAYS_DEFAULT = 30;

let isSqliteSupported: boolean | null = null;

/**
 * Probe whether SQLite is viable in this process by spawning a child
 * process. We must NOT call `new Database()` directly in the main process
 * because on some platforms (e.g. musl libc without the right glibc
 * shims) it segfaults — a hard crash that `try/catch` cannot prevent.
 * The child-process probe safely catches the segfault and we fall back
 * to the in-memory layer.
 */
function testSqliteSupport(): boolean {
  if (isSqliteSupported !== null) return isSqliteSupported;
  try {
    execFileSync(
      process.execPath,
      ['-e', "const d=require('better-sqlite3')(':memory:');d.close();"],
      { timeout: 5000, stdio: 'ignore' }
    );
    isSqliteSupported = true;
  } catch {
    isSqliteSupported = false;
  }
  return isSqliteSupported;
}

export class StorageIndexer {
  private config: StorageConfig;
  private db: any = null;
  private initialized: boolean = false;
  private memSessions: Map<string, SessionRecord> = new Map();
  private memEvents: Event[] = [];
  private memFlags: FlagRecord[] = [];
  private memAttackerActivity: AttackerActivityRecord[] = [];
  private memEnvelopes: Array<{ site_id: string; id: string; session_id: string; sequence: string; ts: number; event_type: string; payload_json: string }> = [];
  // In-memory fallback caches for node identity (needed when SQLite
  // is unavailable and this.db is null, so identity must not change
  // across calls within one instance).
  private memSiteId?: string;
  private memBootId?: string;
  private memStreamId?: string;
  private memChallengeGeneration = 0;
  private memCommandIds = new Map<string, unknown>();
  private memCentralNodes: CentralNodeRecord[] = [];
  private memHoneypotConfig: HoneypotRuntimeConfig | null = null;
  private memTemplates = new Map<string, CentralTemplateRecord>();
  private memBootstrapTokens = new Map<string, { expires_at_ms: number; used_at_ms: number | null; metadata_json: string }>();
  private memCentralEvents: Array<{ event_id: string; site_id: string; stream_id: string; sequence: string; ts: number; event_type: string; payload: unknown }> = [];
  private memPollCursors = new Map<string, { cursor: string | null; events_collected: number; last_poll_at_ms: number | null }>();
  private memExportDeliveries = new Map<string, ExportDeliveryRecord>();
  private memIntegrations: Map<string, IntegrationSetting> = new Map();

  constructor(config: StorageConfig) {
    this.config = { ...config, retentionDays: config.retentionDays ?? RETENTION_DAYS_DEFAULT };
  }

  async init(): Promise<void> {
    if (this.initialized) return;

    if (testSqliteSupport()) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const Database = require('better-sqlite3');
        if (this.config.path && this.config.path !== ':memory:') {
          const dir = path.dirname(this.config.path);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
        }
        this.db = new Database(this.config.path);
        // Migrate existing databases BEFORE adding columns: migrateLegacySchema
        // rebuilds tables with the new composite PK. Running ensureColumn first
        // would make the migration guard (!tableHasColumn('site_id')) skip the
        // rebuild, leaving the legacy single-column PK in place.
        this.migrateLegacySchema();
        // Older node databases may have an events table without the optional
        // session_id column. Add it before createTables creates its index.
        this.ensureColumn('events', 'session_id', 'TEXT');
        this.ensureColumn('event_envelopes', 'site_id', 'TEXT NOT NULL DEFAULT ""');
        this.ensureColumn('event_envelopes', 'sequence', 'TEXT NOT NULL DEFAULT ""');
        this.ensureColumn('central_nodes', 'honeypot_port', 'INTEGER');
        this.ensureColumn('central_nodes', 'service_profile', 'TEXT');
        this.ensureColumn('central_nodes', 'template_id', 'TEXT');
        this.ensureColumn('central_nodes', 'template_version', 'INTEGER');
        this.ensureColumn('central_nodes', 'control_channel', 'TEXT NOT NULL DEFAULT \'legacy\'');
        this.ensureColumn('central_nodes', 'name', 'TEXT');
        this.ensureColumn('central_nodes', 'notes', 'TEXT');
        this.ensureColumn('honeypot_config', 'template_json', 'TEXT');
        this.ensureColumn('attacker_activity', 'site_id', 'TEXT');
        this.createTables();
        this.initialized = true;
        return;
      } catch {
        this.db = null;
      }
    }

    // In-memory fallback: engine still works, evidence is not persisted.
    this.db = null;
    this.initialized = true;
  }

  private ensureColumn(table: string, column: string, definition: string): void {
    if (!this.db) return;
    try {
      const cols = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
      if (!cols.some((c) => c.name === column)) {
        this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
      }
    } catch {
      // Non-fatal.
    }
  }

  private tableHasColumn(table: string, column: string): boolean {
    if (!this.db) return false;
    try {
      const cols = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
      return cols.some((c) => c.name === column);
    } catch {
      return false;
    }
  }

  private migrateLegacySchema(): void {
    if (!this.db) return;
    try {
      // Migrate events: legacy PK is only id. New PK is (site_id, id).
      if (this.tableHasColumn('events', 'id') && !this.tableHasColumn('events', 'site_id')) {
        this.db.exec(`
          CREATE TABLE events_new (
            site_id TEXT NOT NULL,
            id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('session.upsert', 'flag.hit')),
            payload_json TEXT NOT NULL,
            session_id TEXT,
            PRIMARY KEY (site_id, id)
          );
          INSERT INTO events_new SELECT '' AS site_id, id, ts, event_type, payload_json, NULL AS session_id FROM events;
          DROP TABLE events;
          ALTER TABLE events_new RENAME TO events;
          CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
          CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        `);
      }

      // Migrate event_envelopes: legacy PK is only id. New PK is (site_id, id).
      if (this.tableHasColumn('event_envelopes', 'id') && !this.tableHasColumn('event_envelopes', 'site_id')) {
        this.db.exec(`
          CREATE TABLE event_envelopes_new (
            site_id TEXT NOT NULL,
            id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            sequence TEXT NOT NULL,
            ts INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY (site_id, id)
          );
          INSERT INTO event_envelopes_new SELECT '' AS site_id, id, session_id, sequence, ts, event_type, payload_json FROM event_envelopes;
          DROP TABLE event_envelopes;
          ALTER TABLE event_envelopes_new RENAME TO event_envelopes;
          CREATE INDEX IF NOT EXISTS idx_envelopes_site_session ON event_envelopes(site_id, session_id);
          CREATE INDEX IF NOT EXISTS idx_envelopes_ts ON event_envelopes(ts);
          CREATE INDEX IF NOT EXISTS idx_envelopes_sequence ON event_envelopes(sequence);
        `);
      }

      // Migrate central_events: legacy PK is only event_id. New PK is (site_id, event_id).
      if (this.tableHasColumn('central_events', 'event_id') && !this.tableHasColumn('central_events', 'site_id')) {
        this.db.exec(`
          CREATE TABLE central_events_new (
            site_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            stream_id TEXT NOT NULL,
            sequence TEXT NOT NULL,
            ts INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY (site_id, event_id)
          );
          INSERT INTO central_events_new SELECT '' AS site_id, event_id, stream_id, sequence, ts, event_type, payload_json FROM central_events;
          DROP TABLE central_events;
          ALTER TABLE central_events_new RENAME TO central_events;
          CREATE INDEX IF NOT EXISTS idx_central_events_site ON central_events(site_id);
          CREATE INDEX IF NOT EXISTS idx_central_events_session ON central_events(site_id);
        `);
      }

      // Migrate sessions: legacy PK is only session_id. New PK is (site_id, session_id).
      if (this.tableHasColumn('sessions', 'session_id') && !this.tableHasColumn('sessions', 'site_id')) {
        this.db.exec(`
          CREATE TABLE sessions_new (
            site_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            seed_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            state_json TEXT NOT NULL,
            PRIMARY KEY (site_id, session_id)
          );
          INSERT INTO sessions_new SELECT '' AS site_id, session_id, seed_id, created_at, expires_at, state_json FROM sessions;
          DROP TABLE sessions;
          ALTER TABLE sessions_new RENAME TO sessions;
          CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
          CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
        `);
      }

      // Migrate flags: legacy PK is (session_id, flag_code, node_id). New PK is (site_id, session_id, flag_code, node_id).
      if (this.tableHasColumn('flags', 'session_id') && !this.tableHasColumn('flags', 'site_id')) {
        this.db.exec(`
          CREATE TABLE flags_new (
            site_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            flag_code TEXT NOT NULL,
            flag_level INTEGER,
            node_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (site_id, session_id, flag_code, node_id)
          );
          INSERT INTO flags_new SELECT '' AS site_id, session_id, flag_code, flag_level, node_id, created_at FROM flags;
          DROP TABLE flags;
          ALTER TABLE flags_new RENAME TO flags;
          CREATE INDEX IF NOT EXISTS idx_flags_session ON flags(session_id);
          CREATE INDEX IF NOT EXISTS idx_flags_code ON flags(flag_code);
        `);
      }
    } catch {
      // Migration best-effort; if it fails, fall back to memory.
    }
  }

  private createTables(): void {
    if (!this.db) throw new Error('Database not initialized');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS node_identity (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        site_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        seed_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        state_json TEXT NOT NULL,
        PRIMARY KEY (site_id, session_id)
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

      CREATE TABLE IF NOT EXISTS events (
        site_id TEXT NOT NULL,
        id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        event_type TEXT NOT NULL CHECK(event_type IN ('session.upsert', 'flag.hit')),
        payload_json TEXT NOT NULL,
        session_id TEXT,
        PRIMARY KEY (site_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
      CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

      CREATE TABLE IF NOT EXISTS flags (
        site_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        flag_code TEXT NOT NULL,
        flag_level INTEGER,
        node_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (site_id, session_id, flag_code, node_id)
      );
      CREATE INDEX IF NOT EXISTS idx_flags_session ON flags(session_id);
      CREATE INDEX IF NOT EXISTS idx_flags_code ON flags(flag_code);

      CREATE TABLE IF NOT EXISTS event_envelopes (
        site_id TEXT NOT NULL,
        id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        sequence TEXT NOT NULL,
        ts INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        PRIMARY KEY (site_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_envelopes_site_session ON event_envelopes(site_id, session_id);
      CREATE INDEX IF NOT EXISTS idx_envelopes_ts ON event_envelopes(ts);
      CREATE INDEX IF NOT EXISTS idx_envelopes_sequence ON event_envelopes(sequence);

      CREATE TABLE IF NOT EXISTS command_journal (
        command_id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        params_json TEXT NOT NULL,
        issued_at_ms INTEGER NOT NULL,
        outcome_json TEXT NOT NULL,
        executed INTEGER NOT NULL DEFAULT 1
      );
      CREATE INDEX IF NOT EXISTS idx_command_type ON command_journal(type);

      CREATE TABLE IF NOT EXISTS honeypot_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        honeypot_port INTEGER NOT NULL,
        service_profile TEXT NOT NULL,
        template_json TEXT
      );

      CREATE TABLE IF NOT EXISTS honeypot_templates (
        id TEXT NOT NULL,
        version INTEGER NOT NULL,
        profile TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        template_json TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY (id, version)
      );
      CREATE INDEX IF NOT EXISTS idx_honeypot_templates_profile ON honeypot_templates(profile);

      CREATE TABLE IF NOT EXISTS bootstrap_tokens (
        token_hash TEXT PRIMARY KEY,
        expires_at_ms INTEGER NOT NULL,
        used_at_ms INTEGER,
        metadata_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expiry ON bootstrap_tokens(expires_at_ms);

      CREATE TABLE IF NOT EXISTS central_nodes (
        site_id TEXT PRIMARY KEY,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        honeypot_port INTEGER,
        service_profile TEXT,
        template_id TEXT,
        template_version INTEGER,
        name TEXT,
        notes TEXT,
        encrypted_secret TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        encrypted_secret_aad TEXT NOT NULL,
        token_fingerprint TEXT NOT NULL,
        capabilities TEXT NOT NULL DEFAULT '["events.read"]',
        tls TEXT NOT NULL DEFAULT 'http',
        control_channel TEXT NOT NULL DEFAULT 'legacy',
        registered_at_ms INTEGER NOT NULL,
        last_contacted_at_ms INTEGER,
        UNIQUE(host, port)
      );

      CREATE TABLE IF NOT EXISTS poll_cursors (
        site_id TEXT NOT NULL,
        stream_id TEXT NOT NULL,
        cursor TEXT,
        events_collected INTEGER NOT NULL DEFAULT 0,
        last_poll_at_ms INTEGER,
        last_error TEXT,
        PRIMARY KEY (site_id, stream_id)
      );

      CREATE TABLE IF NOT EXISTS central_events (
        site_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        stream_id TEXT NOT NULL,
        sequence TEXT NOT NULL,
        ts INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        PRIMARY KEY (site_id, event_id)
      );
      CREATE INDEX IF NOT EXISTS idx_central_events_site ON central_events(site_id);
      CREATE INDEX IF NOT EXISTS idx_central_events_session ON central_events(site_id);

      CREATE TABLE IF NOT EXISTS export_deliveries (
        destination TEXT PRIMARY KEY,
        last_sequence TEXT,
        sent_count INTEGER NOT NULL DEFAULT 0,
        failed_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        last_attempt_at_ms INTEGER
      );

      CREATE TABLE IF NOT EXISTS integration_settings (
        name TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        label TEXT NOT NULL,
        config_json TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0,
        verified_at_ms INTEGER,
        tested_at_ms INTEGER,
        last_error TEXT,
        updated_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_integrations_kind ON integration_settings(kind);

      CREATE TABLE IF NOT EXISTS attacker_activity (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        site_id TEXT,
        ts INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        path TEXT,
        classification TEXT,
        confidence REAL,
        tooling TEXT,
        level_max INTEGER,
        flags_fired TEXT,
        win_isolated INTEGER,
        meta_detect INTEGER,
        capability REAL,
        intent REAL,
        severity TEXT,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_attacker_activity_session ON attacker_activity(session_id);
      CREATE INDEX IF NOT EXISTS idx_attacker_activity_ts ON attacker_activity(ts);
      CREATE INDEX IF NOT EXISTS idx_attacker_activity_ip ON attacker_activity(ip);
      CREATE INDEX IF NOT EXISTS idx_attacker_activity_site ON attacker_activity(site_id);
    `);
  }

  // Session operations
  async saveSession(session: SessionRecord): Promise<void> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT OR REPLACE INTO sessions (site_id, session_id, seed_id, created_at, expires_at, state_json)
          VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(session.site_id ?? '', session.session_id, session.seed_id, session.created_at, session.expires_at, session.state_json);
        return;
      } catch {
        // Fall through to memory
      }
    }
    this.memSessions.set(session.session_id, session);
  }

  async getSession(sessionId: string): Promise<SessionRecord | null> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?');
        const row = stmt.get(sessionId);
        return row ? this.mapSessionRow(row) : null;
      } catch {
        // Fall through to memory
      }
    }
    return this.memSessions.get(sessionId) || null;
  }

  async listSessions(limit: number = 100): Promise<SessionRecord[]> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare('SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?');
        const rows = stmt.all(limit) as unknown[];
        return rows.map((row: unknown) => this.mapSessionRow(row));
      } catch {
        // Fall through to memory
      }
    }
    return Array.from(this.memSessions.values())
      .sort((a, b) => b.created_at - a.created_at)
      .slice(0, limit);
  }

  async deleteSession(sessionId: string): Promise<void> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        this.db.prepare('DELETE FROM sessions WHERE session_id = ?').run(sessionId);
        return;
      } catch {
        // Fall through to memory
      }
    }
    this.memSessions.delete(sessionId);
  }

  async pruneExpiredSessions(now: number = Date.now()): Promise<number> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const info = this.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
        return info.changes as number;
      } catch {
        // Fall through to memory
      }
    }
    let pruned = 0;
    for (const [id, s] of this.memSessions) {
      if (s.expires_at < now) {
        this.memSessions.delete(id);
        pruned++;
      }
    }
    return pruned;
  }

  async pruneOldData(now: number = Date.now()): Promise<{ events: number; flags: number; attacker_activity: number; sessions: number }> {
    if (!this.initialized) await this.init();
    const cutoff = now - (this.config.retentionDays ?? RETENTION_DAYS_DEFAULT) * 24 * 60 * 60 * 1000;
    let events = 0, flags = 0, attacker = 0, sessions = 0;

    if (this.db) {
      try {
        events = (this.db.prepare('DELETE FROM events WHERE ts < ?').run(cutoff) as { changes: number }).changes;
        flags = (this.db.prepare('DELETE FROM flags WHERE created_at < ?').run(cutoff) as { changes: number }).changes;
        attacker = (this.db.prepare('DELETE FROM attacker_activity WHERE ts < ?').run(cutoff) as { changes: number }).changes;
        sessions = (this.db.prepare('DELETE FROM sessions WHERE created_at < ?').run(cutoff) as { changes: number }).changes;
      } catch {
        // Fall through to memory
      }
    }
    return { events, flags, attacker_activity: attacker, sessions };
  }

  private mapSessionRow(row: unknown): SessionRecord {
    const r = row as Record<string, unknown>;
    return {
      session_id: r.session_id as string,
      seed_id: r.seed_id as string,
      created_at: r.created_at as number,
      expires_at: r.expires_at as number,
      state_json: r.state_json as string,
    };
  }

  async saveEventEnvelope(envelope: EventEnvelope): Promise<void> {
    if (!this.initialized) await this.init();

    const siteId = (envelope as any).site_id ?? '';
    const id = `env_${sha256Hex(JSON.stringify(envelope)).slice(0, 24)}`;
    const sequence = (envelope as any).sequence ?? `${envelope.ts.valueOf()}_${id}`;
    const payload = JSON.stringify(envelope);

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT OR IGNORE INTO event_envelopes (site_id, id, session_id, sequence, ts, event_type, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(siteId, id, envelope.target.session_id, sequence, new Date(envelope.ts).getTime(), envelope.payload.event_type, payload);
        return;
      } catch {
        // Fall through to memory
      }
    }
    if (!this.memEnvelopes.some((e) => e.id === id)) {
      this.memEnvelopes.push({ site_id: siteId, id, session_id: envelope.target.session_id, sequence, ts: new Date(envelope.ts).getTime(), event_type: envelope.payload.event_type, payload_json: payload });
    }
  }

  async getEventEnvelopes(sessionId: string, limit: number = 100): Promise<EventEnvelope[]> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          SELECT payload_json FROM event_envelopes
          WHERE session_id = ?
          ORDER BY ts DESC
          LIMIT ?
        `);
        const rows = stmt.all(sessionId, limit) as Array<{ payload_json: string }>;
        return rows.map((row) => JSON.parse(row.payload_json) as EventEnvelope);
      } catch {
        // Fall through to memory
      }
    }
    return this.memEnvelopes
      .filter((e) => e.session_id === sessionId)
      .slice(-limit)
      .map((row) => JSON.parse(row.payload_json) as EventEnvelope);
  }

  // Event operations
  async saveEvent(event: Event): Promise<void> {
    if (!this.initialized) await this.init();

    const now = Date.now();
    const id = this.generateEventId(event);
    const siteId = event.site_id ?? '';
    const sequence = `${now}_${id}`;

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT OR IGNORE INTO events (site_id, id, ts, event_type, payload_json)
          VALUES (?, ?, ?, ?, ?)
        `);
        stmt.run(siteId, id, now, event.type, JSON.stringify(event));

        const envelopeStmt = this.db.prepare(`
          INSERT OR IGNORE INTO event_envelopes (site_id, id, session_id, sequence, ts, event_type, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        envelopeStmt.run(siteId, id, event.session_id, sequence, now, event.type, JSON.stringify(event));
        return;
      } catch {
        // Fall through to memory
      }
    }
    if (!this.memEvents.some((e) => e === event)) {
      this.memEvents.push(event);
    }
  }

  async getEvents(sessionId: string, limit: number = 100): Promise<Event[]> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          SELECT payload_json FROM events
          WHERE session_id = ?
          ORDER BY ts DESC
          LIMIT ?
        `);
        const rows = stmt.all(sessionId, limit) as Array<{ payload_json: string }>;
        return rows.map((row) => JSON.parse(row.payload_json) as Event);
      } catch {
        // Fall through to memory
      }
    }
    return this.memEvents
      .filter((e) => e.session_id === sessionId)
      .slice(-limit);
  }

  // Flag operations
  async saveFlag(sessionId: string, code: string, level: number | null, nodeId: string): Promise<void> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT OR REPLACE INTO flags (site_id, session_id, flag_code, flag_level, node_id, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run('', sessionId, code, level, nodeId, Date.now());
        return;
      } catch {
        // Fall through to memory
      }
    }
    const key = `${sessionId}|${code}|${nodeId}`;
    if (!this.memFlags.some((f) => `${f.session_id}|${f.flag_code}|${f.node_id}` === key)) {
      this.memFlags.push({
        session_id: sessionId,
        flag_code: code,
        flag_level: level,
        node_id: nodeId,
        created_at: Date.now(),
      });
    }
  }

  async getFlags(sessionId: string): Promise<FlagRecord[]> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare('SELECT * FROM flags WHERE session_id = ?');
        const rows = stmt.all(sessionId) as unknown[];
        return rows.map((row: unknown) => this.mapFlagRow(row));
      } catch {
        // Fall through to memory
      }
    }
    return this.memFlags.filter((f) => f.session_id === sessionId);
  }

  // Attacker activity operations
  async saveAttackerActivity(record: AttackerActivityRecord): Promise<void> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT OR REPLACE INTO attacker_activity
            (id, session_id, site_id, ts, event_type, ip, user_agent, path, classification,
             confidence, tooling, level_max, flags_fired, win_isolated, meta_detect,
             capability, intent, severity, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
          record.id,
          record.session_id,
          record.site_id ?? null,
          record.ts,
          record.event_type,
          record.ip,
          record.user_agent,
          record.path,
          record.classification,
          record.confidence,
          record.tooling ? JSON.stringify(record.tooling) : null,
          record.level_max,
          record.flags_fired ? JSON.stringify(record.flags_fired) : null,
          record.win_isolated ? 1 : 0,
          record.meta_detect ? 1 : 0,
          record.capability,
          record.intent,
          record.severity,
          record.payload_json
        );
        return;
      } catch {
        // Fall through to memory
      }
    }
    this.memAttackerActivity.push(record);
  }

  async listAttackerActivity(
    sessionId: string | null,
    limit: number = 100
  ): Promise<AttackerActivityRecord[]> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = sessionId
          ? this.db.prepare('SELECT * FROM attacker_activity WHERE session_id = ? ORDER BY ts DESC LIMIT ?')
          : this.db.prepare('SELECT * FROM attacker_activity ORDER BY ts DESC LIMIT ?');
        const rows = sessionId ? stmt.all(sessionId, limit) : stmt.all(limit);
        return (rows as unknown[]).map((row: unknown) => this.mapAttackerActivityRow(row));
      } catch {
        // Fall through to memory
      }
    }
    const filtered = sessionId
      ? this.memAttackerActivity.filter((r) => r.session_id === sessionId)
      : this.memAttackerActivity;
    return filtered.sort((a, b) => b.ts - a.ts).slice(0, limit);
  }

  async countAttackerActivity(): Promise<number> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        return (this.db.prepare('SELECT COUNT(*) as count FROM attacker_activity').get() as Record<string, number>).count;
      } catch {
        // Fall through to memory
      }
    }
    return this.memAttackerActivity.length;
  }

  async getAttackers(limit: number = 200): Promise<Array<{ site_id: string | null; ip: string | null; count: number }>> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const rows = this.db.prepare(`
          SELECT site_id, ip, COUNT(*) AS count
          FROM attacker_activity
          WHERE site_id IS NOT NULL AND ip IS NOT NULL AND ip <> ''
          GROUP BY site_id, ip
          ORDER BY count DESC
          LIMIT ?
        `).all(limit) as Array<Record<string, unknown>>;
        return rows.map((row) => ({
          site_id: row.site_id as string | null,
          ip: row.ip as string | null,
          count: Number(row.count),
        }));
      } catch {
        // Fall through to memory
      }
    }
    const counts = new Map<string, number>();
    for (const r of this.memAttackerActivity) {
      if (r.site_id && r.ip) counts.set(`${r.site_id}|${r.ip}`, (counts.get(`${r.site_id}|${r.ip}`) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([key, count]) => {
        const [site_id, ip] = key.split('|');
        return { site_id, ip, count };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  async getEventsBySite(): Promise<Array<{ site_id: string | null; count: number }>> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const rows = this.db.prepare(`
          SELECT site_id, COUNT(*) AS count
          FROM events
          WHERE site_id IS NOT NULL
          GROUP BY site_id
          ORDER BY count DESC
        `).all() as Array<Record<string, unknown>>;
        return rows.map((row) => ({ site_id: row.site_id as string | null, count: Number(row.count) }));
      } catch {
        // Fall through to memory
      }
    }
    const counts = new Map<string, number>();
    for (const e of this.memEvents) {
      const key = e.site_id ?? 'local';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([site_id, count]) => ({ site_id, count }))
      .sort((a, b) => b.count - a.count);
  }

  async getFlagsBySite(): Promise<Array<{ site_id: string | null; count: number }>> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const rows = this.db.prepare(`
          SELECT e.site_id, COUNT(*) AS count
          FROM flags f
          JOIN events e ON e.session_id = f.session_id
          WHERE e.site_id IS NOT NULL
          GROUP BY e.site_id
          ORDER BY count DESC
        `).all() as Array<Record<string, unknown>>;
        return rows.map((row) => ({ site_id: row.site_id as string | null, count: Number(row.count) }));
      } catch {
        // Fall through to memory
      }
    }
    const counts = new Map<string, number>();
    for (const f of this.memFlags) {
      const e = this.memEvents.find((e) => e.session_id === f.session_id);
      const key = e?.site_id ?? 'local';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([site_id, count]) => ({ site_id, count }))
      .sort((a, b) => b.count - a.count);
  }

  async getCentralNode(siteId: string): Promise<CentralNodeRecord | null> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT * FROM central_nodes WHERE site_id = ?').get(siteId) as CentralNodeRecord | undefined;
        return row ? this.mapCentralNodeRow(row) : null;
      } catch {
        // Fall through to memory
      }
    }
    return this.memCentralNodes.find((n) => n.site_id === siteId) ?? null;
  }

  async listCentralNodes(): Promise<CentralNodeRecord[]> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const rows = this.db.prepare('SELECT * FROM central_nodes ORDER BY registered_at_ms DESC').all() as CentralNodeRecord[];
        return rows.map((row) => this.mapCentralNodeRow(row));
      } catch {
        // Fall through to memory
      }
    }
    return [...this.memCentralNodes].sort((a, b) => b.registered_at_ms - a.registered_at_ms);
  }

  async saveCentralNode(node: CentralNodeRecord): Promise<void> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT INTO central_nodes
            (site_id, host, port, honeypot_port, service_profile, template_id, template_version,
             name, notes,
             encrypted_secret, iv, auth_tag, encrypted_secret_aad,
             token_fingerprint, capabilities, tls, control_channel, registered_at_ms,
             last_contacted_at_ms)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(site_id) DO UPDATE SET
            host = excluded.host,
            port = excluded.port,
            honeypot_port = excluded.honeypot_port,
            service_profile = excluded.service_profile,
            template_id = excluded.template_id,
            template_version = excluded.template_version,
            name = COALESCE(excluded.name, central_nodes.name),
            notes = COALESCE(excluded.notes, central_nodes.notes),
            encrypted_secret = excluded.encrypted_secret,
            iv = excluded.iv,
            auth_tag = excluded.auth_tag,
            encrypted_secret_aad = excluded.encrypted_secret_aad,
            token_fingerprint = excluded.token_fingerprint,
            capabilities = excluded.capabilities,
            tls = excluded.tls,
            control_channel = excluded.control_channel,
            registered_at_ms = excluded.registered_at_ms,
            last_contacted_at_ms = excluded.last_contacted_at_ms
        `).run(
          node.site_id, node.host, node.port, node.honeypot_port ?? null,
          node.service_profile ?? null,
          node.template_id ?? null, node.template_version ?? null,
          node.name ?? null, node.notes ?? null,
          node.encrypted_secret, node.iv, node.auth_tag,
          node.encrypted_secret_aad, node.token_fingerprint,
          JSON.stringify(node.capabilities ?? []),
          node.tls ?? 'http',
          node.channel ?? 'legacy',
          node.registered_at_ms, node.last_contacted_at_ms ?? null
        );
        return;
      } catch {
        // Fall through to memory
      }
    }
    const idx = this.memCentralNodes.findIndex((n) => n.site_id === node.site_id);
    if (idx >= 0) this.memCentralNodes[idx] = node;
    else this.memCentralNodes.push(node);
  }

  async updateCentralNodeMetadata(siteId: string, metadata: { name?: string | null; notes?: string | null }): Promise<boolean> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const clauses: string[] = [];
        const params: unknown[] = [];
        if (metadata.name !== undefined) {
          clauses.push('name = ?');
          params.push(metadata.name ?? null);
        }
        if (metadata.notes !== undefined) {
          clauses.push('notes = ?');
          params.push(metadata.notes ?? null);
        }
        if (clauses.length > 0) {
          params.push(siteId);
          const result = this.db.prepare(`UPDATE central_nodes SET ${clauses.join(', ')} WHERE site_id = ?`).run(...params);
          if ((result as { changes: number }).changes > 0) return true;
        }
      } catch {
        // Fall through to memory
      }
    }
    const idx = this.memCentralNodes.findIndex((n) => n.site_id === siteId);
    if (idx >= 0) {
      const existing = this.memCentralNodes[idx];
      this.memCentralNodes[idx] = {
        ...existing,
        name: metadata.name !== undefined ? (metadata.name ?? null) : existing.name,
        notes: metadata.notes !== undefined ? (metadata.notes ?? null) : existing.notes,
      };
      return true;
    }
    return false;
  }

  /** Read the node's durable public-surface configuration. */
  async getHoneypotConfig(): Promise<HoneypotRuntimeConfig | null> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT honeypot_port, service_profile, template_json FROM honeypot_config WHERE id = 1').get() as
          | { honeypot_port: number; service_profile: string; template_json?: string | null }
          | undefined;
        if (!row) return null;
        if (!Number.isInteger(Number(row.honeypot_port)) || !isHoneypotProfile(row.service_profile)) return null;
        let template: HoneypotTemplate | null | undefined;
        if (row.template_json) {
          try {
            const parsed = validateHoneypotTemplate(JSON.parse(row.template_json));
            if (parsed.ok) template = parsed.template;
          } catch {
            template = null;
          }
        }
        return {
          honeypot_port: Number(row.honeypot_port),
          service_profile: normalizeHoneypotProfile(row.service_profile),
          ...(template !== undefined ? { template } : {}),
        };
      } catch {
        // Fall through to memory.
      }
    }
    return this.memHoneypotConfig;
  }

  /** Persist the node's public port/profile as one replaceable setting. */
  async saveHoneypotConfig(config: HoneypotRuntimeConfig): Promise<void> {
    if (!this.initialized) await this.init();
    const normalized: HoneypotRuntimeConfig = {
      honeypot_port: config.honeypot_port,
      service_profile: normalizeHoneypotProfile(config.service_profile),
      template: config.template ?? null,
    };
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT INTO honeypot_config (id, honeypot_port, service_profile, template_json)
          VALUES (1, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            honeypot_port = excluded.honeypot_port,
            service_profile = excluded.service_profile,
            template_json = excluded.template_json
        `).run(
          normalized.honeypot_port,
          normalized.service_profile,
          normalized.template ? JSON.stringify(normalized.template) : null
        );
        this.memHoneypotConfig = normalized;
        return;
      } catch {
        // Fall through to memory.
      }
    }
    this.memHoneypotConfig = normalized;
  }

  /** Store one immutable version of a declarative public-surface template. */
  async saveHoneypotTemplate(template: HoneypotTemplate): Promise<CentralTemplateRecord> {
    if (!this.initialized) await this.init();
    const checked = validateHoneypotTemplate(template);
    if (!checked.ok) throw new Error(checked.error);
    const now = Date.now();
    const key = `${checked.template.id}:${checked.template.version}`;
    const existing = this.memTemplates.get(key);
    const record: CentralTemplateRecord = {
      id: checked.template.id,
      version: checked.template.version,
      profile: checked.template.profile,
      name: checked.template.name,
      description: checked.template.description,
      template_json: JSON.stringify(checked.template),
      created_at_ms: existing?.created_at_ms ?? now,
      updated_at_ms: now,
    };
    if (this.db) {
      try {
        const previous = this.db.prepare('SELECT created_at_ms FROM honeypot_templates WHERE id = ? AND version = ?').get(record.id, record.version) as
          | { created_at_ms: number }
          | undefined;
        const durable = { ...record, created_at_ms: previous?.created_at_ms ?? record.created_at_ms };
        this.db.prepare(`
          INSERT INTO honeypot_templates
            (id, version, profile, name, description, template_json, created_at_ms, updated_at_ms)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id, version) DO UPDATE SET
            profile = excluded.profile,
            name = excluded.name,
            description = excluded.description,
            template_json = excluded.template_json,
            updated_at_ms = excluded.updated_at_ms
        `).run(
          durable.id, durable.version, durable.profile, durable.name, durable.description,
          durable.template_json, durable.created_at_ms, durable.updated_at_ms
        );
        this.memTemplates.set(key, durable);
        return durable;
      } catch {
        // Fall through to the bounded in-memory catalog.
      }
    }
    this.memTemplates.set(key, record);
    return record;
  }

  /** Return one template version, or the newest version when omitted. */
  async getHoneypotTemplate(id: string, version?: number): Promise<HoneypotTemplate | null> {
    if (!this.initialized) await this.init();
    let record: CentralTemplateRecord | undefined;
    if (this.db) {
      try {
        const row = version === undefined
          ? this.db.prepare('SELECT * FROM honeypot_templates WHERE id = ? ORDER BY version DESC LIMIT 1').get(id)
          : this.db.prepare('SELECT * FROM honeypot_templates WHERE id = ? AND version = ?').get(id, version);
        record = row ? this.mapTemplateRow(row) : undefined;
      } catch {
        record = undefined;
      }
    }
    if (!record) {
      const candidates = Array.from(this.memTemplates.values()).filter((item) => item.id === id && (version === undefined || item.version === version));
      record = candidates.sort((a, b) => b.version - a.version)[0];
    }
    if (!record) return null;
    try {
      const parsed = validateHoneypotTemplate(JSON.parse(record.template_json));
      return parsed.ok ? parsed.template : null;
    } catch {
      return null;
    }
  }

  /** List catalog metadata without exposing template body content. */
  async listHoneypotTemplates(): Promise<CentralTemplateRecord[]> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        return (this.db.prepare('SELECT * FROM honeypot_templates ORDER BY id ASC, version DESC').all() as unknown[]).map((row) => this.mapTemplateRow(row));
      } catch {
        // Fall through to memory.
      }
    }
    return Array.from(this.memTemplates.values()).sort((a, b) => a.id.localeCompare(b.id) || b.version - a.version);
  }

  /** Issue a short-lived, single-use bootstrap capability. */
  async issueBootstrapToken(ttlSeconds = 900, metadata: BootstrapTokenMetadata = {}): Promise<{ token: string; expires_at_ms: number }> {
    if (!this.initialized) await this.init();
    const ttl = Math.min(Math.max(Math.floor(ttlSeconds), 60), 24 * 60 * 60);
    const token = randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + ttl * 1000;
    const tokenHash = sha256Hex(token);
    const metadataJson = JSON.stringify(metadata);
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT INTO bootstrap_tokens (token_hash, expires_at_ms, used_at_ms, metadata_json)
          VALUES (?, ?, NULL, ?)
        `).run(tokenHash, expiresAt, metadataJson);
        return { token, expires_at_ms: expiresAt };
      } catch {
        // Fall through to the in-memory store.
      }
    }
    this.memBootstrapTokens.set(tokenHash, { expires_at_ms: expiresAt, used_at_ms: null, metadata_json: metadataJson });
    return { token, expires_at_ms: expiresAt };
  }

  async verifyBootstrapToken(token: string): Promise<boolean> {
    if (!this.initialized) await this.init();
    if (!token || token.length < 32) return false;
    const tokenHash = sha256Hex(token);
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT expires_at_ms, used_at_ms FROM bootstrap_tokens WHERE token_hash = ?').get(tokenHash) as
          | { expires_at_ms: number; used_at_ms: number | null }
          | undefined;
        return Boolean(row && row.used_at_ms === null && Number(row.expires_at_ms) > Date.now());
      } catch {
        // Fall through to memory.
      }
    }
    const record = this.memBootstrapTokens.get(tokenHash);
    return Boolean(record && record.used_at_ms === null && record.expires_at_ms > Date.now());
  }

  /** Atomically mark a bootstrap token used after successful enrollment. */
  async consumeBootstrapToken(token: string): Promise<boolean> {
    if (!this.initialized) await this.init();
    if (!token || token.length < 32) return false;
    const tokenHash = sha256Hex(token);
    const now = Date.now();
    if (this.db) {
      try {
        const result = this.db.prepare(`
          UPDATE bootstrap_tokens SET used_at_ms = ?
          WHERE token_hash = ? AND used_at_ms IS NULL AND expires_at_ms > ?
        `).run(now, tokenHash, now);
        return Number(result.changes) === 1;
      } catch {
        // Fall through to memory.
      }
    }
    const record = this.memBootstrapTokens.get(tokenHash);
    if (!record || record.used_at_ms !== null || record.expires_at_ms <= now) return false;
    record.used_at_ms = now;
    this.memBootstrapTokens.set(tokenHash, record);
    return true;
  }

  async updateCentralNodeLastContact(siteId: string): Promise<void> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        this.db.prepare('UPDATE central_nodes SET last_contacted_at_ms = ? WHERE site_id = ?').run(Date.now(), siteId);
        return;
      } catch {
        // Fall through to memory
      }
    }
    const idx = this.memCentralNodes.findIndex((n) => n.site_id === siteId);
    if (idx >= 0) {
      const node = this.memCentralNodes[idx];
      this.memCentralNodes[idx] = { ...node, last_contacted_at_ms: Date.now() };
    }
  }

  /**
   * Delivery progress for an external destination (e.g. Splunk HEC).
   * One row per destination; the cursor is the last event sequence
   * confirmed delivered, used for deduplication on retry.
   */
  async saveExportDelivery(record: ExportDeliveryRecord): Promise<void> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT INTO export_deliveries
            (destination, last_sequence, sent_count, failed_count, last_error, last_attempt_at_ms)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(destination) DO UPDATE SET
            last_sequence = excluded.last_sequence,
            sent_count = excluded.sent_count,
            failed_count = excluded.failed_count,
            last_error = excluded.last_error,
            last_attempt_at_ms = excluded.last_attempt_at_ms
        `).run(
          record.destination,
          record.last_sequence ?? null,
          record.sent_count,
          record.failed_count,
          record.last_error ?? null,
          record.last_attempt_at_ms ?? null
        );
        return;
      } catch {
        // Fall through to memory
      }
    }
    this.memExportDeliveries.set(record.destination, record);
  }

  async getExportDelivery(destination: string): Promise<ExportDeliveryRecord | null> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT * FROM export_deliveries WHERE destination = ?').get(destination) as
          | ExportDeliveryRecord
          | undefined;
        return row ?? null;
      } catch {
        // Fall through to memory
      }
    }
    return this.memExportDeliveries.get(destination) ?? null;
  }

  async listExportDeliveries(): Promise<ExportDeliveryRecord[]> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        return this.db.prepare('SELECT * FROM export_deliveries ORDER BY destination ASC').all() as ExportDeliveryRecord[];
      } catch {
        // Fall through to memory
      }
    }
    return Array.from(this.memExportDeliveries.values()).sort((a, b) => a.destination.localeCompare(b.destination));
  }

  // --- Integration settings -------------------------------------------------
  async saveIntegrationSetting(setting: IntegrationSetting): Promise<void> {
    if (!this.initialized) await this.init();
    const updatedAt = Date.now();
    const record = {
      name: setting.name,
      kind: setting.kind,
      label: setting.label,
      config_json: setting.config_json,
      enabled: setting.enabled,
      verified_at_ms: setting.verified_at_ms,
      tested_at_ms: setting.tested_at_ms,
      last_error: setting.last_error,
      updated_at_ms: updatedAt,
    };
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT INTO integration_settings (name, kind, label, config_json, enabled, verified_at_ms, tested_at_ms, last_error, updated_at_ms)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(name) DO UPDATE SET
            kind = excluded.kind,
            label = excluded.label,
            config_json = excluded.config_json,
            enabled = excluded.enabled,
            verified_at_ms = excluded.verified_at_ms,
            tested_at_ms = excluded.tested_at_ms,
            last_error = excluded.last_error,
            updated_at_ms = excluded.updated_at_ms
        `).run(record.name, record.kind, record.label, record.config_json, record.enabled, record.verified_at_ms, record.tested_at_ms, record.last_error, updatedAt);
        this.memIntegrations.set(record.name, record);
        return;
      } catch {
        // Fall through to memory
      }
    }
    this.memIntegrations.set(record.name, record);
  }

  async getIntegrationSetting(name: string): Promise<IntegrationSetting | null> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT * FROM integration_settings WHERE name = ?').get(name) as
          | { name: string; kind: IntegrationKind; label: string; config_json: string; enabled: number; verified_at_ms: number | null; tested_at_ms: number | null; last_error: string | null; updated_at_ms: number }
          | undefined;
        return row ? this.mapIntegrationRow(row) : null;
      } catch {
        // Fall through to memory
      }
    }
    return this.memIntegrations.get(name) ?? null;
  }

  async listIntegrationSettings(): Promise<IntegrationSetting[]> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        return this.db.prepare('SELECT * FROM integration_settings ORDER BY kind ASC, name ASC').all() as Array<{ name: string; kind: IntegrationKind; label: string; config_json: string; enabled: number; verified_at_ms: number | null; tested_at_ms: number | null; last_error: string | null; updated_at_ms: number }>;
      } catch {
        // Fall through to memory
      }
    }
    return Array.from(this.memIntegrations.values()).sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
  }

  async deleteIntegrationSetting(name: string): Promise<boolean> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const result = this.db.prepare('DELETE FROM integration_settings WHERE name = ?').run(name);
        this.memIntegrations.delete(name);
        return result.changes > 0;
      } catch {
        // Fall through to memory
      }
    }
    return this.memIntegrations.delete(name);
  }

  private mapIntegrationRow(row: any): IntegrationSetting {
    return {
      name: row.name,
      kind: row.kind,
      label: row.label,
      config_json: row.config_json,
      enabled: row.enabled,
      verified_at_ms: row.verified_at_ms,
      tested_at_ms: row.tested_at_ms,
      last_error: row.last_error,
      updated_at_ms: row.updated_at_ms,
    };
  }

  /**
   * Cursor-based sync state for the central poller. One row per
   * (site_id, stream_id); the cursor is the last exclusive sequence
   * consumed from that stream.
   */
  async savePollCursor(
    siteId: string,
    streamId: string,
    cursor: string | null,
    eventsCollected: number
  ): Promise<void> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT INTO poll_cursors (site_id, stream_id, cursor, events_collected, last_poll_at_ms)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(site_id, stream_id) DO UPDATE SET
            cursor = excluded.cursor,
            events_collected = excluded.events_collected,
            last_poll_at_ms = excluded.last_poll_at_ms
        `).run(siteId, streamId, cursor, eventsCollected, Date.now());
        return;
      } catch {
        // Fall through to memory
      }
    }
    const key = `${siteId}|${streamId}`;
    this.memPollCursors.set(key, { cursor, events_collected: eventsCollected, last_poll_at_ms: Date.now() });
  }

  async getPollCursor(siteId: string, streamId: string): Promise<{ cursor: string | null; events_collected: number; last_poll_at_ms: number | null } | null> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT * FROM poll_cursors WHERE site_id = ? AND stream_id = ?').get(siteId, streamId) as
          | { cursor: string | null; events_collected: number; last_poll_at_ms: number | null }
          | undefined;
        return row ? { cursor: row.cursor, events_collected: row.events_collected, last_poll_at_ms: row.last_poll_at_ms } : null;
      } catch {
        // Fall through to memory
      }
    }
    const key = `${siteId}|${streamId}`;
    const val = this.memPollCursors.get(key);
    return val ?? null;
  }

  /**
   * Persist one polled event idempotently. The primary key is the
   * deterministic event_id, so a page replayed after a crash cannot
   * duplicate rows.
   */
  async saveCentralEvent(
    siteId: string,
    streamId: string,
    eventId: string,
    sequence: string,
    ts: number,
    eventType: string,
    payload: unknown
  ): Promise<void> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT OR IGNORE INTO central_events (site_id, event_id, stream_id, sequence, ts, event_type, payload_json)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(siteId, eventId, streamId, sequence, ts, eventType, JSON.stringify(payload));
        return;
      } catch {
        // Fall through to memory
      }
    }
    if (!this.memCentralEvents.some((e) => e.event_id === eventId && e.site_id === siteId)) {
      this.memCentralEvents.push({ event_id: eventId, site_id: siteId, stream_id: streamId, sequence, ts, event_type: eventType, payload });
    }
  }

  async listCentralEvents(siteId: string | null, limit: number = 500): Promise<Array<{ event_id: string; sequence: string; ts: number; event_type: string; site_id: string; stream_id: string; payload: unknown }>> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        let rows: Array<Record<string, unknown>>;
        if (siteId) {
          rows = this.db.prepare(`
            SELECT event_id, sequence, ts, event_type, site_id, stream_id, payload_json
            FROM central_events
            WHERE site_id = ?
            ORDER BY ts DESC, sequence DESC
            LIMIT ?
          `).all(siteId, limit) as Array<Record<string, unknown>>;
        } else {
          rows = this.db.prepare(`
            SELECT event_id, sequence, ts, event_type, site_id, stream_id, payload_json
            FROM central_events
            ORDER BY ts DESC, sequence DESC
            LIMIT ?
          `).all(limit) as Array<Record<string, unknown>>;
        }
        return rows.map((row) => ({
          event_id: row.event_id as string,
          sequence: row.sequence as string,
          ts: row.ts as number,
          event_type: row.event_type as string,
          site_id: row.site_id as string,
          stream_id: row.stream_id as string,
          payload: JSON.parse(row.payload_json as string),
        }));
      } catch {
        // Fall through to memory
      }
    }
    const filtered = siteId ? this.memCentralEvents.filter((e) => e.site_id === siteId) : this.memCentralEvents;
    return [...filtered]
      .sort((a, b) => (b.ts - a.ts) || String(b.sequence).localeCompare(String(a.sequence)))
      .slice(0, limit)
      .map((e) => ({
        event_id: e.event_id,
        sequence: e.sequence,
        ts: e.ts,
        event_type: e.event_type,
        site_id: e.site_id,
        stream_id: e.stream_id,
        payload: e.payload,
      }));
  }

  async countCentralEvents(siteId: string): Promise<number> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        return (this.db.prepare('SELECT COUNT(*) as count FROM central_events WHERE site_id = ?').get(siteId) as Record<string, number>).count;
      } catch {
        // Fall through to memory
      }
    }
    return this.memCentralEvents.filter((e) => e.site_id === siteId).length;
  }

  async getCentralEventsBySite(): Promise<Array<{ site_id: string | null; count: number }>> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const rows = this.db.prepare(`
          SELECT site_id, COUNT(*) AS count
          FROM central_events
          GROUP BY site_id
          ORDER BY count DESC
        `).all() as Array<Record<string, unknown>>;
        return rows.map((row) => ({ site_id: row.site_id as string | null, count: Number(row.count) }));
      } catch {
        // Fall through to memory
      }
    }
    const counts = new Map<string, number>();
    for (const e of this.memCentralEvents) {
      counts.set(e.site_id, (counts.get(e.site_id) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([site_id, count]) => ({ site_id, count }))
      .sort((a, b) => b.count - a.count);
  }

  async getEventPage(
    siteId: string,
    cursor: string | null,
    limit: number
  ): Promise<{
    events: Array<{ event_id: string; sequence: string; payload: unknown }>;
    next_cursor: string | null;
    high_watermark: string;
    has_more: boolean;
  }> {
    if (!this.initialized) await this.init();
    if (!this.db) return { events: [], next_cursor: cursor ?? null, high_watermark: cursor ?? '', has_more: false };
    try {
      const rows = cursor
        ? this.db.prepare(`
            SELECT id, sequence, payload_json
            FROM event_envelopes
            WHERE site_id = ? AND sequence > ?
            ORDER BY sequence ASC
            LIMIT ?
          `).all(siteId, cursor, limit) as Array<Record<string, unknown>>
        : this.db.prepare(`
            SELECT id, sequence, payload_json
            FROM event_envelopes
            WHERE site_id = ?
            ORDER BY sequence ASC
            LIMIT ?
          `).all(siteId, limit) as Array<Record<string, unknown>>;

      const events = rows.map((row) => ({
        event_id: row.id as string,
        sequence: row.sequence as string,
        payload: JSON.parse(row.payload_json as string),
      }));

      // Always keep the last confirmed cursor so the next poll continues
      // from here instead of restarting from the beginning.
      const lastSeq = rows.length > 0
        ? (rows[rows.length - 1]?.sequence as string) ?? null
        : (cursor ?? null);
      const hasMore = rows.length === limit;

      return { events, next_cursor: lastSeq, high_watermark: lastSeq ?? '', has_more: hasMore };
    } catch {
      return { events: [], next_cursor: cursor ?? null, high_watermark: cursor ?? '', has_more: false };
    }
  }

  /**
   * Idempotent command execution: a command with the same command_id will
   * not execute twice. Returns the stored outcome on duplicate invocations.
   */
  async executeCommand(
    commandId: string,
    type: string,
    params: Record<string, unknown>,
    handler?: () => Promise<unknown>
  ): Promise<{ executed: boolean; outcome: unknown }> {
    const existing = await this.getStoredCommand(commandId);
    if (existing) {
      return { executed: false, outcome: existing.outcome };
    }

    const outcome = handler ? await handler() : await this.runCommand(type, params);
    await this.storeCommand(commandId, type, params, outcome);
    return { executed: true, outcome };
  }

  private async getStoredCommand(commandId: string): Promise<{ outcome: unknown } | null> {
    if (this.db) {
      try {
        const row = this.db.prepare('SELECT outcome_json FROM command_journal WHERE command_id = ?').get(commandId) as
          | { outcome_json: string }
          | undefined;
        if (!row) return null;
        return { outcome: JSON.parse(row.outcome_json) };
      } catch {
        return null;
      }
    }
    // In-memory fallback: return cached outcome if the command was seen.
    const outcome = this.memCommandIds.get(commandId);
    return outcome ? { outcome } : null;
  }

  private async storeCommand(
    commandId: string,
    type: string,
    params: Record<string, unknown>,
    outcome: unknown
  ): Promise<void> {
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT OR IGNORE INTO command_journal (command_id, type, params_json, issued_at_ms, outcome_json)
          VALUES (?, ?, ?, ?, ?)
        `).run(commandId, type, JSON.stringify(params), Date.now(), JSON.stringify(outcome));
        return;
      } catch {
        // Fall through to memory
      }
    }
    this.memCommandIds.set(commandId, outcome);
  }

  /**
   * Dispatch a command type to the appropriate handler. Unknown commands
   * produce a structured rejection outcome rather than throwing.
   */
  private async runCommand(type: string, params: Record<string, unknown>): Promise<unknown> {
    switch (type) {
      case 'control.restart':
        return {
          action: 'restart',
          message: 'Restart signal queued',
          restart_after: 'response',
        };
      case 'control.rotate_challenges':
        return {
          action: 'rotate_challenges',
          message: 'Challenge generation rotated',
          generation_increment: 1,
        };
      case 'settings.update':
        return { action: 'settings_update', updated: Object.keys(params) };
      default:
        return { action: 'noop', message: `Unknown command type: ${type}` };
    }
  }

  private mapCentralNodeRow(row: unknown): CentralNodeRecord {
    const r = row as Record<string, unknown>;
    let capabilities: string[] = [];
    try {
      const raw = r.capabilities as string;
      if (raw) capabilities = JSON.parse(raw) as string[];
    } catch {
      capabilities = [];
    }
    return {
      site_id: r.site_id as string,
      host: r.host as string,
      port: Number(r.port),
      encrypted_secret: r.encrypted_secret as string,
      iv: r.iv as string,
      auth_tag: r.auth_tag as string,
      encrypted_secret_aad: r.encrypted_secret_aad as string,
      token_fingerprint: r.token_fingerprint as string,
      honeypot_port: r.honeypot_port == null ? null : Number(r.honeypot_port),
      service_profile: typeof r.service_profile === 'string' ? r.service_profile : null,
      template_id: typeof r.template_id === 'string' ? r.template_id : null,
      template_version: r.template_version == null ? null : Number(r.template_version),
      name: typeof r.name === 'string' ? r.name : (r.name == null ? null : String(r.name)),
      notes: typeof r.notes === 'string' ? r.notes : (r.notes == null ? null : String(r.notes)),
      capabilities: capabilities as CentralNodeCapability[],
      tls: 'http',
      channel: r.control_channel === 'encrypted' ? 'encrypted' : 'legacy',
      registered_at_ms: Number(r.registered_at_ms),
      last_contacted_at_ms: r.last_contacted_at_ms == null ? null : Number(r.last_contacted_at_ms),
    };
  }

  private mapTemplateRow(row: unknown): CentralTemplateRecord {
    const r = row as Record<string, unknown>;
    return {
      id: String(r.id),
      version: Number(r.version),
      profile: normalizeHoneypotProfile(r.profile),
      name: String(r.name ?? ''),
      description: String(r.description ?? ''),
      template_json: String(r.template_json ?? ''),
      created_at_ms: Number(r.created_at_ms),
      updated_at_ms: Number(r.updated_at_ms),
    };
  }

  async getActivityBySite(): Promise<Array<{ site_id: string | null; count: number }>> {
    if (!this.initialized) await this.init();
    if (this.db) {
      try {
        const rows = this.db.prepare(`
          SELECT site_id, COUNT(*) AS count
          FROM attacker_activity
          WHERE site_id IS NOT NULL
          GROUP BY site_id
          ORDER BY count DESC
        `).all() as Array<Record<string, unknown>>;
        return rows.map((row) => ({ site_id: row.site_id as string | null, count: Number(row.count) }));
      } catch {
        // Fall through to memory
      }
    }
    const counts = new Map<string, number>();
    for (const r of this.memAttackerActivity) {
      const key = r.site_id ?? 'local';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([site_id, count]) => ({ site_id, count }))
      .sort((a, b) => b.count - a.count);
  }

  private mapAttackerActivityRow(row: unknown): AttackerActivityRecord {
    const r = row as Record<string, unknown>;
    return {
      id: r.id as string,
      session_id: r.session_id as string,
      site_id: (r.site_id as string) ?? null,
      ts: r.ts as number,
      event_type: r.event_type as string,
      ip: (r.ip as string) ?? null,
      user_agent: (r.user_agent as string) ?? '',
      path: (r.path as string) ?? null,
      classification: (r.classification as string) ?? null,
      confidence: (r.confidence as number) ?? null,
      tooling: r.tooling ? JSON.parse(r.tooling as string) : null,
      level_max: (r.level_max as number) ?? null,
      flags_fired: r.flags_fired ? JSON.parse(r.flags_fired as string) : null,
      win_isolated: r.win_isolated ? Boolean(r.win_isolated) : null,
      meta_detect: r.meta_detect ? Boolean(r.meta_detect) : null,
      capability: (r.capability as number) ?? null,
      intent: (r.intent as number) ?? null,
      severity: (r.severity as string) ?? null,
      payload_json: r.payload_json as string,
    };
  }

  private mapFlagRow(row: unknown): FlagRecord {
    const r = row as Record<string, unknown>;
    return {
      session_id: r.session_id as string,
      flag_code: r.flag_code as string,
      flag_level: r.flag_level as number | null,
      node_id: r.node_id as string,
      created_at: r.created_at as number,
    };
  }

  // Statistics
  async getStats(): Promise<StorageStats> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const sessionCount = (this.db.prepare('SELECT COUNT(*) as count FROM sessions').get() as Record<string, number>).count;
        const eventCount = (this.db.prepare('SELECT COUNT(*) as count FROM events').get() as Record<string, number>).count;
        const flagCount = (this.db.prepare('SELECT COUNT(*) as count FROM flags').get() as Record<string, number>).count;
        const attackerActivityCount = (this.db.prepare('SELECT COUNT(*) as count FROM attacker_activity').get() as Record<string, number>).count;
        const envelopeCount = (this.db.prepare('SELECT COUNT(*) as count FROM event_envelopes').get() as Record<string, number>).count;

        return {
          sessions: sessionCount,
          events: eventCount,
          flags: flagCount,
          attacker_activity: attackerActivityCount,
          event_envelopes: envelopeCount,
          size_bytes: this.getDbSize(),
        };
      } catch {
        // Fall through to memory
      }
    }

    return {
      sessions: this.memSessions.size,
      events: this.memEvents.length,
      flags: this.memFlags.length,
      attacker_activity: this.memAttackerActivity.length,
      event_envelopes: this.memEnvelopes.length,
      size_bytes: this.getDbSize(),
    };
  }

  private getDbSize(): number {
    try {
      const dbPath = this.db && this.db.name ? this.db.name : this.config.path;
      if (fs.existsSync(dbPath)) {
        const stat = fs.statSync(dbPath);
        return stat.size;
      }
      return 0;
    } catch {
      return 0;
    }
  }

  // Utility methods
  async replaySession(sessionId: string): Promise<Event[]> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          SELECT payload_json FROM events
          WHERE session_id = ?
          ORDER BY ts ASC
        `);
        const rows = stmt.all(sessionId) as Array<{ payload_json: string }>;
        return rows.map((row) => JSON.parse(row.payload_json) as Event);
      } catch {
        // Fall through to memory
      }
    }
    return this.memEvents
      .filter((e) => e.session_id === sessionId)
      .sort((a, b) => a.ts.localeCompare(b.ts));
  }

  async clear(): Promise<void> {
    if (!this.initialized) await this.init();

    if (this.db) {
      try {
        this.db.exec('DELETE FROM events');
        this.db.exec('DELETE FROM flags');
        this.db.exec('DELETE FROM sessions');
        this.db.exec('DELETE FROM attacker_activity');
        this.db.exec('DELETE FROM event_envelopes');
      } catch {
        // Fall through to memory
      }
    }
    this.memEvents = [];
    this.memFlags = [];
    this.memSessions.clear();
    this.memAttackerActivity = [];
    this.memEnvelopes = [];
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initialized = false;
    }
  }

  // --- Node identity ------------------------------------------------------

  /**
   * Return the stable site_id for this node. Create one on first call and
   * persist it so every restart gets the same opaque identity. New deploys
   * get a random ID; an explicit VAIVAR_SITE_ID env var is respected when
   * set, but the persisted random value is never overwritten by a redeploy.
   */
  async getSiteId(): Promise<string> {
    if (this.memSiteId) return this.memSiteId;
    const stored = await this.getIdentity('site_id');
    if (stored) {
      this.memSiteId = stored;
      return stored;
    }
    const generated = randomBytes(8).toString('hex');
    this.memSiteId = generated;
    await this.setIdIdentity('site_id', generated);
    return generated;
  }

  /**
   * The current process boot identifier — changes on every process start.
   * Intentionally NOT persisted: central uses it to detect a fresh launch
   * after a restart. Cached in memory so repeated reads within one process
   * are stable.
   */
  async getBootId(): Promise<string> {
    if (this.memBootId) return this.memBootId;
    const generated = `${Date.now().toString(36)}_${randomBytes(4).toString('hex')}`;
    this.memBootId = generated;
    return generated;
  }

  /**
   * A persistent stream identifier for the event log. Changed only when the
   * schema is incompatible (detected by a missing expected column), not by
   * normal restarts.
   */
  async getStreamId(): Promise<string> {
    if (this.memStreamId) return this.memStreamId;
    const stored = await this.getIdentity('stream_id');
    if (stored) {
      this.memStreamId = stored;
      return stored;
    }
    const generated = `st_${randomBytes(8).toString('hex')}`;
    this.memStreamId = generated;
    await this.setIdIdentity('stream_id', generated);
    return generated;
  }

  /**
   * Current challenge-generation counter. Incremented when central requests
   * a rotation. Shared across restarts.
   */
  async getChallengeGeneration(): Promise<number> {
    const raw = await this.getIdentity('challenge_generation');
    if (raw) {
      const n = parseInt(raw, 10);
      this.memChallengeGeneration = Number.isFinite(n) ? n : 0;
      return this.memChallengeGeneration;
    }
    if (this.memChallengeGeneration) return this.memChallengeGeneration;
    return 0;
  }

  async setChallengeGeneration(n: number): Promise<void> {
    this.memChallengeGeneration = n;
    await this.setIdIdentity('challenge_generation', String(n));
  }

  // --- Internal helpers ---------------------------------------------------

  private async getIdentity(key: string): Promise<string | null> {
    if (!this.db) return null;
    try {
      const row = this.db.prepare('SELECT value FROM node_identity WHERE key = ?').get(key) as
        | { value: string }
        | undefined;
      return row?.value ?? null;
    } catch {
      return null;
    }
  }

  private async setIdIdentity(key: string, value: string): Promise<void> {
    if (!this.db) return;
    try {
      this.db.prepare('INSERT OR REPLACE INTO node_identity (key, value) VALUES (?, ?)').run(key, value);
    } catch {
      // Non-fatal; identity missing on next boot is acceptable.
    }
  }

  /**
   * Deterministic event id: identical payloads map to the same id, so
   * replaying a session does not duplicate evidence. No timestamp dependency.
   */
  private generateEventId(event: Event): string {
    return `e_${sha256Hex(JSON.stringify(event)).slice(0, 24)}`;
  }
}

export const createStorage = (pathOrConfig: string | StorageConfig): StorageIndexer => {
  const config = typeof pathOrConfig === 'string' ? { path: pathOrConfig } : pathOrConfig;
  return new StorageIndexer({ ...config, retentionDays: config.retentionDays ?? RETENTION_DAYS_DEFAULT });
};

export const RETENTION_DAYS = RETENTION_DAYS_DEFAULT;
