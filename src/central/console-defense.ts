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

import { createHmac } from 'crypto';

// Console self-defense: Central is the one component that must never be
// owned. The console is not only a target — it is a sensor. Every failed
// auth, brute-force attempt, and scan is a high-confidence hostile signal
// (real operators rarely mistype 64-hex tokens). Those signals are
// recorded as attacker_activity rows under site_id "central" so the
// dashboard, metrics, Splunk HEC, and OpenCTI see the console's own
// attackers through the same telemetry pipeline as honeypot attackers.
//
// Design contract: Central authentication policy.

// ── Named constants (no magic numbers in the logic) ──────────────────────────
/** Hard cap on ban-duration escalation exponent (base * 2^EXP). */
export const MAX_BAN_ESCALATION_EXPONENT = 12;
/** Before a scan would overflow memory, prune oldest distinct paths by this factor. */
export const SCAN_PATH_OVERFLOW_FACTOR = 4;
/** Client-IP keys are truncated to this length to bound memory. */
export const MAX_IP_LENGTH = 64;
/** site_id under which console attackers are persisted, shared with server.ts. */
export const CENTRAL_SITE_ID = 'central';
/** Confidence assigned to console-attacker signals (operators never mistype 64-hex). */
export const CONSOLE_ATTACKER_CONFIDENCE = 90;
/** Interval at which the server drains in-memory state into storage. */
export const CONSOLE_DEFENSE_DRAIN_INTERVAL_MS = 15_000;

export type ConsoleAttackKind = 'login_bruteforce' | 'api_probe' | 'path_scan';

export interface ConsoleDefenseConfig {
  /** Failures on /api/v1/login within the window before a ban. */
  readonly loginLimit: number;
  /** Window for login failures (ms). */
  readonly loginWindowMs: number;
  /** 401s on authenticated endpoints within the window before a ban. */
  readonly apiProbeLimit: number;
  /** Window for API auth failures (ms). */
  readonly apiProbeWindowMs: number;
  /** Distinct unknown paths within the window before a ban. */
  readonly scanPathLimit: number;
  /** Window for path scanning (ms). */
  readonly scanWindowMs: number;
  /** Base ban duration (ms); escalates exponentially per re-offense. */
  readonly banBaseMs: number;
  /** Hard ceiling on ban duration (ms). */
  readonly banCeilingMs: number;
  /** Max tracked IPs (memory bound; oldest evicted). */
  readonly maxTrackedIps: number;
}

export const DEFAULT_CONSOLE_DEFENSE_CONFIG: ConsoleDefenseConfig = {
  loginLimit: 5,
  loginWindowMs: 10 * 60_000,
  apiProbeLimit: 30,
  apiProbeWindowMs: 60_000,
  scanPathLimit: 40,
  scanWindowMs: 60_000,
  banBaseMs: 60_000,
  banCeilingMs: 60 * 60_000,
  maxTrackedIps: 10_000,
};

export interface ConsoleDecision {
  /** True when the request must be answered with 429. */
  readonly banned: boolean;
  /** Seconds the client should wait before retrying (Retry-After). */
  readonly retryAfterSeconds: number;
  /** Attack kinds observed for this IP so far. */
  readonly kinds: ConsoleAttackKind[];
}

export interface ConsoleAttackerSnapshot {
  readonly ip: string;
  readonly loginFailures: number;
  readonly apiProbeFailures: number;
  readonly scannedPaths: number;
  readonly firstSeen: number;
  readonly lastSeen: number;
  readonly banned: boolean;
  readonly banUntil: number;
  readonly offenseCount: number;
}

interface IpState {
  loginFailures: number;
  loginWindowStart: number;
  apiProbeFailures: number;
  apiProbeWindowStart: number;
  scannedPaths: Map<string, number>;
  scanWindowStart: number;
  firstSeen: number;
  lastSeen: number;
  banUntil: number;
  offenseCount: number;
}

/** Pure: derives the client IP from the request shape (no I/O). */
export function clientIp(req: { headers: Record<string, unknown>; socket: { remoteAddress?: string } }, trustProxy: boolean): string {
  if (trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd.length > 0) {
      const first = fwd.split(',')[0]?.trim();
      if (first) return first.slice(0, MAX_IP_LENGTH);
    }
  }
  return req.socket.remoteAddress || 'unknown';
}

/** Pure: computes the ban duration for a given offense count (exponential). */
export function banDurationMs(config: Pick<ConsoleDefenseConfig, 'banBaseMs' | 'banCeilingMs'>, offenseCount: number): number {
  const exponent = Math.min(offenseCount - 1, MAX_BAN_ESCALATION_EXPONENT);
  return Math.min(config.banBaseMs * 2 ** exponent, config.banCeilingMs);
}

/** Pure: severity label for a given ban state. */
export function consoleAttackerSeverity(banned: boolean): 'critical' | 'medium' {
  return banned ? 'critical' : 'medium';
}

/** Pure: level_max for a given ban state. */
export function consoleAttackerLevel(banned: boolean): 5 | 3 {
  return banned ? 5 : 3;
}

/** HMAC key for deriving stable attacker-activity record IDs. */
export const CONSOLE_ATTACKER_HMAC_KEY = 'console-attacker';
/** Length of derived attacker-activity record IDs (hex). */
export const ATTACKER_RECORD_ID_LENGTH = 32;

/** Pure: stable record id for a console-attacker observation. */
export function consoleAttackerId(ip: string, now: number): string {
  return createHmac('sha256', CONSOLE_ATTACKER_HMAC_KEY).update(`${ip}:${now}`).digest('hex').slice(0, ATTACKER_RECORD_ID_LENGTH);
}

/**
 * Fail-closed per-IP defense for the Central console. Pure module: no I/O,
 * injectable clock for deterministic tests. Persistence (attacker_activity
 * rows under site_id "central") is drained by the server via snapshot().
 */
export class ConsoleDefense {
  private readonly config: ConsoleDefenseConfig;
  private readonly now: () => number;
  private readonly states = new Map<string, IpState>();

  constructor(config: Partial<ConsoleDefenseConfig> = {}, now: () => number = Date.now) {
    this.config = { ...DEFAULT_CONSOLE_DEFENSE_CONFIG, ...config };
    this.now = now;
  }

  /** Derive the client IP for rate-limit keys. Trusts x-forwarded-for only
   *  when explicitly enabled (reverse proxy deployments). */
  static clientIp(req: { headers: Record<string, unknown>; socket: { remoteAddress?: string } }, trustProxy: boolean): string {
    return clientIp(req as never, trustProxy);
  }

  private stateFor(ip: string): IpState {
    // Evict oldest when over capacity (Map preserves insertion order).
    if (!this.states.has(ip) && this.states.size >= this.config.maxTrackedIps) {
      const oldest = this.states.keys().next();
      if (!oldest.done) this.states.delete(oldest.value);
    }
    let st = this.states.get(ip);
    if (!st) {
      st = {
        loginFailures: 0,
        loginWindowStart: 0,
        apiProbeFailures: 0,
        apiProbeWindowStart: 0,
        scannedPaths: new Map(),
        scanWindowStart: 0,
        firstSeen: this.now(),
        lastSeen: this.now(),
        banUntil: 0,
        offenseCount: 0,
      };
      this.states.set(ip, st);
    }
    return st;
  }

  /** Check (and never record) whether an IP is currently banned. */
  banned(ip: string): boolean {
    const st = this.states.get(ip);
    if (!st) return false;
    return st.banUntil > this.now();
  }

  /** Remaining ban seconds for an IP (0 when not banned). */
  banSecondsRemaining(ip: string): number {
    const st = this.states.get(ip);
    if (!st) return 0;
    const remain = st.banUntil - this.now();
    return remain > 0 ? Math.ceil(remain / 1000) : 0;
  }

  private ban(st: IpState): void {
    st.offenseCount += 1;
    const duration = banDurationMs(this.config, st.offenseCount);
    st.banUntil = Math.max(st.banUntil, this.now() + duration);
  }

  private slideWindow(st: IpState, windowStartKey: 'loginWindowStart' | 'apiProbeWindowStart' | 'scanWindowStart', windowMs: number): void {
    // When the window has elapsed, reset to a clean window (current call).
    const now = this.now();
    if (now - st[windowStartKey] > windowMs) {
      st[windowStartKey] = now;
      if (windowStartKey === 'loginWindowStart') st.loginFailures = 0;
      else if (windowStartKey === 'apiProbeWindowStart') st.apiProbeFailures = 0;
      else st.scannedPaths.clear();
    }
  }

  /** Record a failed operator login. May trigger a ban. */
  recordLoginFailure(ip: string): ConsoleDecision {
    const st = this.stateFor(ip);
    st.lastSeen = this.now();
    this.slideWindow(st, 'loginWindowStart', this.config.loginWindowMs);
    st.loginFailures += 1;
    if (st.loginFailures >= this.config.loginLimit) {
      st.loginFailures = 0; // window consumed by the ban
      this.ban(st);
    }
    return this.decide(ip);
  }

  /** Record a 401 on an authenticated endpoint (token probing). */
  recordApiProbeFailure(ip: string): ConsoleDecision {
    const st = this.stateFor(ip);
    st.lastSeen = this.now();
    this.slideWindow(st, 'apiProbeWindowStart', this.config.apiProbeWindowMs);
    st.apiProbeFailures += 1;
    if (st.apiProbeFailures >= this.config.apiProbeLimit) {
      st.apiProbeFailures = 0;
      this.ban(st);
    }
    return this.decide(ip);
  }

  /** Record a request to an unknown path (scanner behavior). */
  recordScanPath(ip: string, path: string): ConsoleDecision {
    const st = this.stateFor(ip);
    st.lastSeen = this.now();
    this.slideWindow(st, 'scanWindowStart', this.config.scanWindowMs);
    if (st.scannedPaths.size >= this.config.scanPathLimit * SCAN_PATH_OVERFLOW_FACTOR) {
      st.scannedPaths.clear();
      st.scanWindowStart = this.now();
    }
    st.scannedPaths.set(path, (st.scannedPaths.get(path) ?? 0) + 1);
    if (st.scannedPaths.size >= this.config.scanPathLimit) {
      st.scannedPaths.clear();
      this.ban(st);
    }
    return this.decide(ip);
  }

  /** A successful operator login resets prior login failures (fat-finger tolerance). */
  recordLoginSuccess(ip: string): void {
    const st = this.states.get(ip);
    if (!st) return;
    st.loginFailures = 0;
    st.loginWindowStart = this.now();
  }

  private decide(ip: string): ConsoleDecision {
    const st = this.states.get(ip);
    const kinds: ConsoleAttackKind[] = [];
    if (st) {
      if (st.loginFailures > 0) kinds.push('login_bruteforce');
      if (st.apiProbeFailures > 0) kinds.push('api_probe');
      if (st.scannedPaths.size > 0) kinds.push('path_scan');
    }
    const seconds = this.banSecondsRemaining(ip);
    return { banned: seconds > 0, retryAfterSeconds: seconds, kinds };
  }

  /** Immutable view of all tracked attackers (for persistence + metrics). */
  snapshot(): ConsoleAttackerSnapshot[] {
    const now = this.now();
    const out: ConsoleAttackerSnapshot[] = [];
    for (const [ip, st] of this.states) {
      out.push({
        ip,
        loginFailures: st.loginFailures,
        apiProbeFailures: st.apiProbeFailures,
        scannedPaths: st.scannedPaths.size,
        firstSeen: st.firstSeen,
        lastSeen: st.lastSeen,
        banned: st.banUntil > now,
        banUntil: st.banUntil,
        offenseCount: st.offenseCount,
      });
    }
    return out;
  }

  /** Number of currently banned IPs. */
  bannedCount(): number {
    const now = this.now();
    let n = 0;
    for (const st of this.states.values()) if (st.banUntil > now) n += 1;
    return n;
  }
}
