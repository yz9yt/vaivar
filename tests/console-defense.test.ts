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

import { describe, it, expect } from 'vitest';
import { ConsoleDefense, type ConsoleDefenseConfig } from '../src/central/console-defense';

// ── Pure test fixtures ────────────────────────────────────────────────────
// No scattered literals: every IP is derived deterministically from a seed.
const ip = (seed: number): string => `10.0.${(seed >> 8) & 0xff}.${(seed & 0xff) + 1}`;

const config = (over: Partial<ConsoleDefenseConfig> = {}): ConsoleDefenseConfig => ({
  loginLimit: 3,
  loginWindowMs: 1_000,
  apiProbeLimit: 2,
  apiProbeWindowMs: 1_000,
  scanPathLimit: 2,
  scanWindowMs: 1_000,
  banBaseMs: 1_000,
  banCeilingMs: 8_000,
  maxTrackedIps: 10,
  ...over,
});

type Clock = { now: () => number; advance: (ms: number) => void };
const clock = (): Clock => {
  let t = 0;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
};

// Higher-order driver: applies `count` failures of one kind to derived IPs.
// Returns the IPs used so callers can assert on them without literals.
const hammer = (
  def: ConsoleDefense,
  kind: 'login' | 'api' | 'scan',
  count: number,
  ipOf: (i: number) => string = ip,
): string[] =>
  Array.from({ length: count }, (_, i) => {
    const addr = ipOf(i);
    if (kind === 'login') def.recordLoginFailure(addr);
    else if (kind === 'api') def.recordApiProbeFailure(addr);
    else def.recordScanPath(addr, `/p/${i}`);
    return addr;
  });

const constant = (value: string) => (): string => value;

describe('ConsoleDefense', () => {
  it('ban triggers after loginLimit failures and reports Retry-After', () => {
    const c = clock();
    const def = new ConsoleDefense(config(), c.now);
    const target = ip(1);
    hammer(def, 'login', 3, constant(target));
    expect(def.banned(target)).toBe(true);
    expect(def.banSecondsRemaining(target) > 0).toBeTruthy();
  });

  it('a successful login clears prior failures', () => {
    const c = clock();
    const def = new ConsoleDefense(config(), c.now);
    const target = ip(2);
    hammer(def, 'login', 2, constant(target));
    def.recordLoginSuccess(target);
    expect(def.banned(target)).toBe(false);
  });

  it('api-probe failures ban after apiProbeLimit', () => {
    const c = clock();
    const def = new ConsoleDefense(config(), c.now);
    const target = ip(3);
    hammer(def, 'api', 2, constant(target));
    expect(def.banned(target)).toBe(true);
  });

  it('distinct-path scanning bans after scanPathLimit', () => {
    const c = clock();
    const def = new ConsoleDefense(config(), c.now);
    const target = ip(4);
    hammer(def, 'scan', 2, constant(target));
    expect(def.banned(target)).toBe(true);
  });

  it('ban duration escalates on repeat offense', () => {
    const c = clock();
    const def = new ConsoleDefense(config({ banBaseMs: 1_000 }), c.now);
    const target = ip(5);
    hammer(def, 'login', 3, constant(target));
    const first = def.banSecondsRemaining(target);
    c.advance(2_000);
    hammer(def, 'login', 3, constant(target));
    expect(def.banSecondsRemaining(target) >= first * 2).toBeTruthy();
  });

  it('failure window slides past its TTL, old failures do not accumulate', () => {
    const c = clock();
    const def = new ConsoleDefense(config({ loginLimit: 3, loginWindowMs: 1_000 }), c.now);
    const target = ip(6);
    hammer(def, 'login', 2, constant(target));
    expect(def.banned(target)).toBe(false);
    c.advance(1_001);
    def.recordLoginFailure(target); // window reset → only 1 in the new window
    expect(def.banned(target)).toBe(false);
  });

  it('snapshot reports every tracked attacker with its observed kinds', () => {
    const c = clock();
    const def = new ConsoleDefense(config(), c.now);
    hammer(def, 'login', 1, constant(ip(10)));
    hammer(def, 'api', 1, constant(ip(11)));
    hammer(def, 'scan', 1, constant(ip(12)));
    const byIp = new Map(def.snapshot().map((s) => [s.ip, s]));
    expect(byIp.get(ip(10))!.loginFailures).toBe(1);
    expect(byIp.get(ip(12))!.scannedPaths).toBe(1);
  });

  it('clientIp trusts x-forwarded-for only when trustProxy is set', () => {
    const req = {
      headers: { 'x-forwarded-for': `${ip(20)}, ${ip(21)}` },
      socket: { remoteAddress: ip(22) },
    };
    expect(ConsoleDefense.clientIp(req as never, true)).toBe(ip(20));
    expect(ConsoleDefense.clientIp(req as never, false)).toBe(ip(22));
  });

  it('bannedCount tracks only currently-banned IPs', () => {
    const c = clock();
    const def = new ConsoleDefense(config(), c.now);
    hammer(def, 'login', 2, (i) => ip(30 + i)); // two distinct IPs, 1 failure each
    expect(def.bannedCount()).toBe(0);
    hammer(def, 'login', 3, constant(ip(30))); // ban ip(30)
    expect(def.bannedCount()).toBe(1);
  });
});
