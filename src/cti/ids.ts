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

// STIX 2.1 deterministic identity helpers + IOC policy.
//
// Policy (from the product design): the ONLY indicator candidates are real attacker
// infrastructure (IPv4/IPv6). Maze URLs, seeds, flags and hostnames invented
// by the generator are observables at most and NEVER indicators.

import { deterministicUuid } from '../hash/stable';

export type StixType =
  | 'incident'
  | 'ipv4-addr'
  | 'ipv6-addr'
  | 'url'
  | 'tool'
  | 'note'
  | 'identity'
  | 'relationship'
  | 'infrastructure';

/**
 * Deterministic STIX id: same (type, value) always maps to the same UUID so
 * OpenCTI deduplicates and replays are idempotent.
 */
export const generateSTIXId = (type: string, value: string): string =>
  `${type}--${deterministicUuid('vaivar', `${type}|${value}`)}`;

/**
 * Strict IOC policy: only real attacker infrastructure (IPs) is indicator
 * material. Everything else is correlation-only.
 */
export const isIndicatorCandidate = (obj: { type: string; labels?: string[] }): boolean => {
  if (obj.type !== 'ipv4-addr' && obj.type !== 'ipv6-addr') return false;
  // Never treat the honeypot's own infrastructure as attacker IOC.
  const labels = obj.labels ?? [];
  if (labels.includes('vaivar-self')) return false;
  return true;
};

export interface IOCValidation {
  readonly isIndicator: boolean;
  readonly reason: string;
}

export const validateAsIndicator = (fact: { type: string; value?: string }): IOCValidation => {
  if (fact.type === 'url') {
    return { isIndicator: false, reason: 'Generated/maze URL: correlation-only, not an IOC' };
  }
  if (fact.type === 'ipv4-addr' || fact.type === 'ipv6-addr') {
    if (isPrivateIp(fact.value ?? '')) {
      return { isIndicator: false, reason: 'Private/reserved address: not attacker infrastructure' };
    }
    return { isIndicator: true, reason: 'Real attacker IP' };
  }
  return { isIndicator: false, reason: `Type ${fact.type} is not an indicator candidate` };
};

const isPrivateIp = (ip: string): boolean => {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const [, a, b] = v4;
    if (a === '10' || a === '127' || a === '0') return true;
    if (a === '192' && b === '168') return true;
    if (a === '172' && parseInt(b, 10) >= 16 && parseInt(b, 10) <= 31) return true;
    if (a === '169' && b === '254') return true;
    return false;
  }
  // v6: loopback, link-local, ULA, documentation ranges
  const v6 = ip.toLowerCase();
  return (
    v6 === '::1' ||
    v6.startsWith('fe80') ||
    v6.startsWith('fc') ||
    v6.startsWith('fd') ||
    v6.startsWith('2001:db8')
  );
};
