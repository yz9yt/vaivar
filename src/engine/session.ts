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

// Session engine: per-session seed derivation, progress tracking, scoring,
// and vaivar.event.v1 emission. This is the defensive core that ties the
// graph, levels, classifier, and telemetry together.

import { ok, err, type Result } from '../fp/core';
import { sha256Hex } from '../hash/stable';
import { deriveSeed as deriveSessionSeed } from './derivation';
import type { BudgetLimits, Node } from '../types/common';
import { DEFAULT_BUDGET } from '../types/common';
import type {
  Event,
  SessionEvent,
  AgentClass,
  Severity,
} from '../types/events';
import { createSessionEvent, createFlagEvent, foldEvents } from '../types/events';
import { computeCapability, computeIntent, computeMatrix } from '../scoring/capability';
import { verifyFlag } from '../levels/checker';
import { isMetaProbe, classifyRequest, recordPattern, type RequestPattern } from '../classifier/analyzer';
import { generateNode } from '../graph/generator';
import { dwellFlagCode } from './flags';
import type { StorageIndexer } from '../storage/indexer';
import { buildWorldPlan, canAccessPath, type WorldPlan } from './world-plan';
import type { SessionRecord } from '../storage/types';

export interface SessionEngineConfig {
  /** Master secret; per-session seeds are derived from it. */
  readonly masterSecret: string;
  readonly budget: BudgetLimits;
  /** Dwell (seconds) after which FLAG_DWELL fires. */
  readonly dwellFlagSeconds: number;
  readonly skins?: readonly string[];
  /** Optional durable store for active session rehydration. */
  readonly storage?: StorageIndexer;
}

export const DEFAULT_ENGINE_CONFIG: SessionEngineConfig = {
  masterSecret: '',
  budget: DEFAULT_BUDGET,
  dwellFlagSeconds: 3600,
  skins: ['http', 'mcp'],
};

export interface SessionSnapshot {
  readonly sessionId: string;
  readonly createdAt: number;
  readonly lastSeenAt: number;
  readonly levelMax: number;
  readonly levelsClosed: number[];
  readonly winIsolated: boolean;
  readonly metaDetect: boolean;
  readonly challengeGeneration: number;
  readonly intent: {
    readonly dwellSeconds: number;
    readonly requests: number;
    readonly retries: number;
    readonly returningDays: number;
    readonly bytesRead: number;
    readonly nodesVisited: number;
  };
  readonly budget: { nodes: number; bytes: number; requests: number };
}

export interface SubmitResult {
  readonly accepted: boolean;
  readonly meta: boolean;
  readonly levelMax: number;
  /** Present when accepted: the code kind that closed. */
  readonly kind?: 'FLAG_LEVEL' | 'FLAG_WIN';
  readonly level?: number | null;
}

interface SessionState {
  sessionId: string;
  seed: string;
  /** Generation captured at birth; rotation never rewrites active sessions. */
  challengeGeneration: number;
  createdAt: number;
  lastSeenAt: number;
  levelMax: number;
  levelsClosed: number[];
  flagsFired: string[];
  winIsolated: boolean;
  metaDetect: boolean;
  metaSignals: string[];
  requests: number;
  retries: number;
  bytesRead: number;
  nodesVisited: number;
  submittedCodes: Set<string>;
  agentClass: AgentClass;
  tooling: string[];
  confidence: number;
  lastIp: string | null;
  lastUserAgent: string;
  /** Emitted events for fold/replay. */
  events: Event[];
  /** Rolling request pattern for classifier (kept bounded by caller). */
  patterns: RequestPattern | null;
  dwellFlagFired: boolean;
  worldPlanKey: string;
}

const SESSION_TTL_MS = 48 * 3600 * 1000;

export class SessionEngine {
  private readonly config: SessionEngineConfig;
  private readonly sessions: Map<string, SessionState> = new Map();
  /** Sessions grouped by attacker fingerprint hash for returning-day tracking. */
  private readonly fingerprints: Map<string, { firstSeen: number; sessions: Set<string> }> = new Map();
  /** Current challenge-generation counter. Incremented when central
   *  requests a rotation. Each session captures this value at birth so
   *  rotation never mutates the world of active sessions. */
  private challengeGeneration: number = 0;
  /** Per-session WorldPlan cache (KHM-02 deep path validation). */
  private readonly planCache: Map<string, WorldPlan> = new Map();

  constructor(config: SessionEngineConfig = DEFAULT_ENGINE_CONFIG) {
    if (!config.masterSecret || config.masterSecret.length < 32) {
      throw new Error('SessionEngine requires a master secret of at least 32 characters');
    }
    this.config = config;
    if (!this.config.skins) this.config = { ...this.config, skins: ['http', 'mcp'] };
  }

  // -- Seed derivation ------------------------------------------------------

  /**
   * Per-session seed: HKDF-like derivation from the master secret. The seed
   * binds all world content for this session (anti-KB: two sessions never
   * share a world). The persistent `challenge_generation` is folded into
   * the derivation so a rotation produces a genuinely new universe space
   * for future sessions while leaving active sessions untouched (their
   * seed was captured at birth).
   */
  deriveSeed(sessionId: string, attackerFp: string, generation?: number): string {
    const gen = generation ?? this.challengeGeneration;
    return deriveSessionSeed(this.config.masterSecret, 'vaivar.session.v1', sessionId, attackerFp, gen);
  }

  /** Current persistent challenge-generation used for new-session seeds. */
  get currentChallengeGeneration(): number {
    return this.challengeGeneration;
  }

  /**
   * Set the live generation counter (read once from storage at boot, then
   * bumped by rotate_challenges). Only affects sessions created afterwards.
   */
  setChallengeGeneration(n: number): void {
    if (!Number.isInteger(n) || n < 0) {
      throw new Error('Challenge generation must be a non-negative integer');
    }
    this.challengeGeneration = n;
  }

  // -- Session lifecycle ----------------------------------------------------

  /**
   * Fingerprint policy (KHM-01):
   * - Same opaque credential + minor UA variation => resume existing session.
   * - Strong fingerprint change (different UA family, different IP) => new session,
   *   even if the same public `sessionId` is reused. This prevents transcript reuse.
   */
  private uaFamily(ua: string): string {
    // First token before first whitespace or opening paren.
    const match = ua.match(/^([^\s(\/]+)/);
    return match ? match[1].toLowerCase() : ua.slice(0, 12).toLowerCase();
  }

  /** Check whether two fingerprints belong to the same attacker family. */
  private sameFingerprintFamily(ipA: string | null, ipB: string | null, uaA: string, uaB: string): boolean {
    // Same IP family (first 3 octets): IPv4 with at most one octet difference.
    const ipFamily = (ip: string): string => ip.split('.').slice(0, 3).join('.');
    const ipMatch = ipA && ipB ? ipFamily(ipA) === ipFamily(ipB) : true;

    // Same UA family (browser/tool identity): first word comparison.
    const uaMatch = this.uaFamily(uaA) === this.uaFamily(uaB);

    // Both must match; missing IP is treated as unknown (still compare UA).
    return ipMatch && uaMatch;
  }

  private planFor(s: SessionState): WorldPlan {
    let plan = this.planCache.get(s.worldPlanKey);
    if (!plan) {
      plan = buildWorldPlan(s.seed, s.challengeGeneration);
      this.planCache.set(s.worldPlanKey, plan);
      if (this.planCache.size > 500) this.planCache.clear();
    }
    return plan;
  }

  getOrCreate(sessionId: string, src: { ip: string | null; userAgent: string }): SessionState {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      // KHM-01: if the fingerprint changed too much, do NOT resume the old session.
      if (!this.sameFingerprintFamily(existing.lastIp, src.ip, existing.lastUserAgent, src.userAgent)) {
        // Create a fresh session with a new opaque credential.
        const newId = this.generateSessionId();
        const fpHash = sha256Hex(`${src.ip ?? 'noip'}|${src.userAgent}`).slice(0, 16);
        const seed = this.deriveSeed(newId, fpHash);
        const state: SessionState = {
          sessionId: newId,
          seed,
          challengeGeneration: this.challengeGeneration,
          createdAt: Date.now(),
          lastSeenAt: Date.now(),
          levelMax: 0,
          levelsClosed: [],
          flagsFired: [],
          winIsolated: false,
          metaDetect: false,
          metaSignals: [],
          requests: 0,
          retries: 0,
          bytesRead: 0,
          nodesVisited: 0,
          submittedCodes: new Set(),
          agentClass: 'unknown',
          tooling: [],
          confidence: 0,
          lastIp: src.ip,
          lastUserAgent: src.userAgent,
          events: [],
          patterns: null,
          dwellFlagFired: false,
          worldPlanKey: sha256Hex(seed).slice(0, 16),
        };
        this.sessions.set(newId, state);
        this.recordFingerprint(fpHash, newId);
        return state;
      }
      existing.lastSeenAt = Date.now();
      if (src.ip) existing.lastIp = src.ip;
      if (src.userAgent) existing.lastUserAgent = src.userAgent;
      return existing;
    }

    const fpHash = sha256Hex(`${src.ip ?? 'noip'}|${src.userAgent}`).slice(0, 16);
    const state: SessionState = {
      sessionId,
      seed: this.deriveSeed(sessionId, fpHash),
      challengeGeneration: this.challengeGeneration,
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      levelMax: 0,
      levelsClosed: [],
      flagsFired: [],
      winIsolated: false,
      metaDetect: false,
      metaSignals: [],
      requests: 0,
      retries: 0,
      bytesRead: 0,
      nodesVisited: 0,
      submittedCodes: new Set(),
      agentClass: 'unknown',
      tooling: [],
      confidence: 0,
      lastIp: src.ip,
      lastUserAgent: src.userAgent,
      events: [],
      patterns: null,
      dwellFlagFired: false,
      worldPlanKey: sha256Hex(this.deriveSeed(sessionId, fpHash)).slice(0, 16),
    };
    this.sessions.set(sessionId, state);
    this.recordFingerprint(fpHash, sessionId);

    return state;
  }

  private generateSessionId(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return hex;
  }

  private recordFingerprint(fpHash: string, sessionId: string): void {
    const fp = this.fingerprints.get(fpHash);
    if (fp) {
      const returningDays = Math.floor((Date.now() - fp.firstSeen) / 86400000);
      if (returningDays >= 1) {
        // intent bump handled in scoring
      }
    }
    this.fingerprints.set(fpHash, {
      firstSeen: fp?.firstSeen ?? Date.now(),
      sessions: fp ? fp.sessions : new Set(),
    });
    this.fingerprints.get(fpHash)!.sessions.add(sessionId);
  }

  get(sessionId: string): SessionState | undefined {
    return this.sessions.get(sessionId);
  }

  snapshot(sessionId: string): SessionSnapshot | null {
    const s = this.sessions.get(sessionId);
    if (!s) return null;
    return {
      sessionId: s.sessionId,
      createdAt: s.createdAt,
      lastSeenAt: s.lastSeenAt,
      levelMax: s.levelMax,
      levelsClosed: [...s.levelsClosed],
      winIsolated: s.winIsolated,
      metaDetect: s.metaDetect,
      challengeGeneration: s.challengeGeneration,
      intent: {
        dwellSeconds: Math.floor((s.lastSeenAt - s.createdAt) / 1000),
        requests: s.requests,
        retries: s.retries,
        returningDays: this.returningDaysFor(s),
        bytesRead: s.bytesRead,
        nodesVisited: s.nodesVisited,
      },
      budget: { nodes: s.nodesVisited, bytes: s.bytesRead, requests: s.requests },
    };
  }

  private returningDaysFor(s: SessionState): number {
    const fpHash = sha256Hex(`${s.lastIp ?? 'noip'}|${s.lastUserAgent}`).slice(0, 16);
    const fp = this.fingerprints.get(fpHash);
    if (!fp) return 0;
    return Math.floor((Date.now() - fp.firstSeen) / 86400000);
  }

  // -- Request lifecycle ----------------------------------------------------

  /** Record a request against the session; updates intent + dwell flag. */
  recordRequest(sessionId: string, src: { ip: string | null; userAgent: string }, bytes: number): void {
    const s = this.getOrCreate(sessionId, src);
    s.requests += 1;
    s.bytesRead += bytes;
    this.checkDwell(s);
  }

  recordRetry(sessionId: string, src: { ip: string | null; userAgent: string }): void {
    const s = this.getOrCreate(sessionId, src);
    s.retries += 1;
  }

  private checkDwell(s: SessionState): void {
    if (s.dwellFlagFired) return;
    const dwell = (Date.now() - s.createdAt) / 1000;
    if (dwell >= this.config.dwellFlagSeconds) {
      s.dwellFlagFired = true;
      s.flagsFired.push('FLAG_DWELL');
      s.events.push(
        createFlagEvent({
          sessionId: s.sessionId,
          code: 'FLAG_DWELL',
          level: null,
          flagId: dwellFlagCode(s.seed),
          skin: 'intent',
          nodeId: 'dwell',
          hint: `Dwell exceeded ${this.config.dwellFlagSeconds}s`,
        })
      );
    }
  }

  /** Register a meta-detection signal (L9). */
  markMetaSignal(sessionId: string, signal: string): void {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    s.metaSignals.push(signal);
    if (s.metaSignals.length > 0 && !s.metaDetect) {
      s.metaDetect = true;
    }
  }

  /** Convenience: inspect free text for meta probes and record if matched. */
  observeMetaProbe(sessionId: string, text: string): boolean {
    if (isMetaProbe(text)) {
      this.markMetaSignal(sessionId, text.slice(0, 120));
      return true;
    }
    return false;
  }

  // -- Node budget ----------------------------------------------------------

  /**
   * KHM-02: validate deep paths against the per-session WorldPlan.
   * Root and shallow paths always resolve; deep paths (depth >= 3) require
   * the session's capability level to cover the path's gate.
   */
  private winIsolatedAllowed(s: SessionState, path: string): boolean {
    if (s.winIsolated) return true;
    const plan = this.planFor(s);
    return canAccessPath(plan, s.levelMax, path);
  }

  serveNode(sessionId: string, src: { ip: string | null; userAgent: string }, path: string): Result<{ node: Node; degraded: boolean }, string> {
    const s = this.getOrCreate(sessionId, src);
    // Update rolling request pattern for classifier (KHM-09).
    const now = Date.now();
    s.patterns = recordPattern(s.patterns, { method: 'GET', path, headers: {}, userAgent: src.userAgent }, now);
    if (s.patterns && s.patterns.requestCount >= 3) {
      const classification = classifyRequest({ method: 'GET', path, headers: {}, userAgent: src.userAgent }, [s.patterns]);
      s.agentClass = classification.class;
      s.tooling = classification.tools;
      s.confidence = classification.confidence;
    }
    // KHM-02: deep paths must be capabilities derived from this session's seed.
    // A deep URL from another session resolves to a cheap corridor, not the node.
    if (!this.winIsolatedAllowed(s, path)) {
      return err('Not found');
    }
    if (s.winIsolated) {
      // KHM-12: after L10 the session is in an explicit enclosure state.
      // All subsequent navigation is served from the isolated namespace,
      // never from the main graph.
      const res = generateNode({
        seed: s.seed,
        path: `${path}|enclosure`,
        budget: this.config.budget,
        currentNodeCount: this.config.budget.maxNodes,
        currentBytes: this.config.budget.maxBytes,
      });
      if (!res.ok) return err(res.error);
      return ok({ node: res.value, degraded: false });
    }
    if (s.nodesVisited >= this.config.budget.maxNodes || s.bytesRead >= this.config.budget.maxBytes) {
      // Degraded corridor instead of an error (no limit disclosure).
      const res = generateNode({
        seed: s.seed,
        path,
        budget: this.config.budget,
        currentNodeCount: this.config.budget.maxNodes,
        currentBytes: this.config.budget.maxBytes,
      });
      if (!res.ok) return err(res.error);
      return ok({ node: res.value, degraded: true });
    }
    const res = generateNode({
      seed: s.seed,
      path,
      budget: this.config.budget,
      currentNodeCount: s.nodesVisited,
      currentBytes: s.bytesRead,
    });
    if (!res.ok) return err(res.error);
    s.nodesVisited += 1;
    s.bytesRead += res.value.metadata.size;
    this.checkDwell(s);
    return ok({ node: res.value, degraded: false });
  }

  // -- Flag submission ------------------------------------------------------

  /**
   * Submit a code found in the world. Verifies against the session seed,
   * applies progression rules, fires flags/events.
   */
  submitCode(
    sessionId: string,
    src: { ip: string | null; userAgent: string },
    code: string,
    skin: string,
    nodeId: string
  ): SubmitResult {
    const s = this.getOrCreate(sessionId, src);

    if (s.submittedCodes.has(code)) {
      return { accepted: false, meta: false, levelMax: s.levelMax };
    }
    s.submittedCodes.add(code);

    if (this.observeMetaProbe(sessionId, code)) {
      return { accepted: false, meta: true, levelMax: s.levelMax };
    }

    // The win token closes level 10; level flags close their own level.
    const isWin = code === sha256Hex(`${s.seed}|win`).slice(0, 32);
    const targetLevel = isWin ? 10 : this.guessTargetLevel(s, code);

    const verdict = verifyFlag(s.seed, targetLevel, code, s.levelMax);
    if (!verdict.accepted) {
      if (verdict.meta) this.markMetaSignal(sessionId, 'decoy-submission');
      return { accepted: false, meta: verdict.meta, levelMax: s.levelMax };
    }

    // Accepted: advance state.
    if (isWin) {
      s.winIsolated = true;
      s.levelMax = Math.max(s.levelMax, 10);
      s.flagsFired.push('FLAG_WIN');
      s.events.push(
        createFlagEvent({
          sessionId: s.sessionId,
          code: 'FLAG_WIN',
          level: 10,
          flagId: code,
          skin,
          nodeId,
          hint: 'Win: isolated enclosure reached',
        })
      );
      return { accepted: true, meta: false, levelMax: s.levelMax, kind: 'FLAG_WIN', level: 10 };
    }

    s.levelMax = Math.max(s.levelMax, targetLevel);
    if (!s.levelsClosed.includes(targetLevel)) s.levelsClosed.push(targetLevel);
    s.flagsFired.push('FLAG_LEVEL');
    s.events.push(
      createFlagEvent({
        sessionId: s.sessionId,
        code: 'FLAG_LEVEL',
        level: targetLevel,
        flagId: code,
        skin,
        nodeId,
        hint: `Level ${targetLevel} closed`,
      })
    );
    return { accepted: true, meta: false, levelMax: s.levelMax, kind: 'FLAG_LEVEL', level: targetLevel };
  }

  /**
   * Which level a submitted code claims. Level flags are unambiguous: they
   * must match one of the seed-derived codes; anything else targets the next
   * reachable level (which will fail verification).
   */
  private guessTargetLevel(s: SessionState, code: string): number {
    for (let level = 1; level <= 9; level++) {
      if (code === sha256Hex(`${s.seed}|flag|${level}`).slice(0, 32)) return level;
    }
    return Math.min(9, s.levelMax + 1);
  }

  // -- Event emission -------------------------------------------------------

  /**
   * Build the current session.upsert event (scores computed from live state)
   * and append it to the session log. Callers forward it to sinks.
   */
  emitSessionEvent(sessionId: string): SessionEvent | null {
    const s = this.sessions.get(sessionId);
    if (!s) return null;

    const dwellSeconds = Math.floor((s.lastSeenAt - s.createdAt) / 1000);
    const levelsPerHour = dwellSeconds > 0 ? s.levelsClosed.length / (dwellSeconds / 3600) : 0;
    const capability = computeCapability({
      levelMax: s.levelMax,
      levelsPerHour,
      metaDetect: s.metaDetect,
      win: s.winIsolated,
    });
    const intent = computeIntent({
      dwellSeconds,
      requests: s.requests,
      retries: s.retries,
      returningDays: this.returningDaysFor(s),
      bytesRead: s.bytesRead,
    });

    const event = createSessionEvent({
      sessionId: s.sessionId,
      seedId: sha256Hex(s.seed).slice(0, 16),
      src: {
        ip: s.lastIp,
        userAgent: s.lastUserAgent,
        headersInteresting: {},
      },
      agent: {
        class: s.agentClass,
        tooling: s.tooling,
        confidence: s.confidence,
      },
      progress: {
        level_max: s.levelMax,
        levels_closed: [...s.levelsClosed],
        win_isolated: s.winIsolated,
        meta_detect: s.metaDetect,
      },
      intent: {
        dwell_seconds: dwellSeconds,
        requests: s.requests,
        retries: s.retries,
        returning_days: this.returningDaysFor(s),
        bytes_read: s.bytesRead,
        nodes_visited: s.nodesVisited,
      },
      scores: { capability, intent },
      skins: [...(this.config.skins ?? ['http', 'mcp'])],
      flagsFired: [...s.flagsFired],
      severityHint: this.severityFor(capability, intent),
    });

    s.events.push(event);
    return event;
  }

  private severityFor(capability: number, intent: number): Severity {
    const { alert } = computeMatrix(capability, intent);
    switch (alert) {
      case 'maximum':
      case 'serious':
        return 'critical';
      case 'alert':
      case 'capability_alert':
        return 'high';
      case 'intent_alert':
      case 'bounded_threat':
        return 'medium';
      case 'watch':
      case 'proving':
        return 'low';
      default:
        return 'info';
    }
  }

  /** Drain the raw event log for a session (for persistence/replay). */
  drainEvents(sessionId: string): Event[] {
    const s = this.sessions.get(sessionId);
    if (!s) return [];
    return s.events.splice(0, s.events.length);
  }

  /** Peek without draining. */
  peekEvents(sessionId: string): Event[] {
    return this.sessions.get(sessionId)?.events ?? [];
  }

  /** Fold the event log into the latest authoritative session snapshot. */
  foldedSession(sessionId: string): SessionEvent | null {
    return foldEvents(this.peekEvents(sessionId));
  }


  private serializeSession(state: SessionState): SessionRecord {
    return {
      session_id: state.sessionId,
      seed_id: sha256Hex(state.seed).slice(0, 16),
      created_at: state.createdAt,
      expires_at: state.lastSeenAt + SESSION_TTL_MS,
      state_json: JSON.stringify({
        seed: state.seed,
        challengeGeneration: state.challengeGeneration,
        levelMax: state.levelMax,
        levelsClosed: state.levelsClosed,
        flagsFired: state.flagsFired,
        winIsolated: state.winIsolated,
        metaDetect: state.metaDetect,
        metaSignals: state.metaSignals,
        requests: state.requests,
        retries: state.retries,
        bytesRead: state.bytesRead,
        nodesVisited: state.nodesVisited,
        submittedCodes: [...state.submittedCodes],
        agentClass: state.agentClass,
        tooling: state.tooling,
        confidence: state.confidence,
        lastIp: state.lastIp,
        lastUserAgent: state.lastUserAgent,
        dwellFlagFired: state.dwellFlagFired,
      }),
    };
  }

  private deserializeSession(record: SessionRecord): SessionState {
    const data = JSON.parse(record.state_json);
    return {
      sessionId: record.session_id,
      seed: data.seed,
      challengeGeneration: data.challengeGeneration,
      createdAt: record.created_at,
      lastSeenAt: record.expires_at - SESSION_TTL_MS,
      levelMax: data.levelMax,
      levelsClosed: data.levelsClosed,
      flagsFired: data.flagsFired,
      winIsolated: data.winIsolated,
      metaDetect: data.metaDetect,
      metaSignals: data.metaSignals,
      requests: data.requests,
      retries: data.retries,
      bytesRead: data.bytesRead,
      nodesVisited: data.nodesVisited,
      submittedCodes: new Set(data.submittedCodes),
      agentClass: data.agentClass,
      tooling: data.tooling,
      confidence: data.confidence,
      lastIp: data.lastIp,
      lastUserAgent: data.lastUserAgent,
      events: [],
      patterns: null,
      dwellFlagFired: data.dwellFlagFired,
      worldPlanKey: sha256Hex(data.seed).slice(0, 16),
    };
  }

  async rehydrateFromStorage(): Promise<void> {
    const storage = this.config.storage;
    if (!storage) return;
    const sessions = await storage.listSessions(1000);
    const now = Date.now();
    for (const record of sessions) {
      if (record.expires_at < now) continue;
      const state = this.deserializeSession(record);
      this.sessions.set(state.sessionId, state);
    }
  }

  async persistSession(state: SessionState): Promise<void> {
    const storage = this.config.storage;
    if (!storage) return;
    const record = this.serializeSession(state);
    await storage.saveSession(record);
  }

  async pruneExpired(now: number = Date.now()): Promise<void> {
    const expired = this.expireIdle(now);
    const storage = this.config.storage;
    if (!storage) return;
    for (const id of expired) {
      await storage.deleteSession(id);
    }
  }

  // -- Flush / persistence ----------------------------------------------------

  /**
   * Build a fresh session.upsert event for every live session and drain each
   * pending event log. Callers write the returned events to the bus / storage.
   */
  flushAll(): { events: Event[]; sessionEvents: SessionEvent[] } {
    const events: Event[] = [];
    const sessionEvents: SessionEvent[] = [];
    for (const [id] of this.sessions) {
      const upsert = this.emitSessionEvent(id);
      if (upsert) sessionEvents.push(upsert);
      events.push(...this.drainEvents(id));
    }
    return { events, sessionEvents };
  }

  expireIdle(now: number = Date.now()): string[] {
    const evicted: string[] = [];
    for (const [id, s] of this.sessions) {
      if (now - s.lastSeenAt > SESSION_TTL_MS) {
        this.sessions.delete(id);
        // Emit a final close event before eviction.
        const final = this.emitSessionEvent(id);
        if (final) {
          evicted.push(id);
        }
      }
    }
    return evicted;
  }

  get sessionCount(): number {
    return this.sessions.size;
  }

  /** Public operator-facing projection: live sessions without seeds. */
  listSessions(): SessionSnapshot[] {
    const out: SessionSnapshot[] = [];
    for (const s of this.sessions.values()) {
      const snap = this.snapshot(s.sessionId);
      if (snap) out.push(snap);
    }
    return out;
  }

  /** Internal raw access to live session states (for persistence). */
  listSessionsRaw(): SessionState[] {
    return Array.from(this.sessions.values());
  }
}
