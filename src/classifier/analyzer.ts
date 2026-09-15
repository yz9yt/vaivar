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

import type { Request, Classification } from '../types/classifier';

export interface RequestPattern {
  readonly path: string;
  readonly method: string;
  readonly userAgent: string;
  readonly headers: Record<string, string>;
  readonly timestamps: number[];
  readonly requestCount: number;
  readonly uniquePaths: number;
}

type SignalType =
  | 'tooling_detected'
  | 'semantic_links'
  | 'burst'
  | 'think_time'
  | 'wordlist_scan'
  | 'state_absence';

interface Signal {
  readonly type: SignalType;
  readonly confidence: number;
  readonly tool?: string;
  readonly interval?: number;
}

/** Paths that only dumb scanners bother probing. */
const SCANNER_PATH_RE =
  /\/(\.env|\.git|wp-admin|wp-login|phpmyadmin|admin|backup|config\.php|actuator|\.aws|cgi-bin)/i;

const KNOWN_AGENT_RE = /(claude|anthropic|openai|cursor|copilot|gemini|llm|agent|bot-scrape)/i;

const detectTooling = (userAgent: string): string | null => {
  const ua = userAgent.toLowerCase();
  if (ua.includes('claude')) return 'claude-code';
  if (ua.includes('cursor')) return 'cursor';
  if (ua.includes('copilot')) return 'copilot';
  if (ua.includes('gemini')) return 'gemini-cli';
  if (ua.includes('openai') || ua.includes('chatgpt')) return 'openai';
  if (ua.includes('llm') || ua.includes('agent')) return 'generic-agent';
  return null;
};

const calculateAvgInterval = (timestamps: number[]): number => {
  if (timestamps.length < 2) return Infinity;
  const intervals = timestamps.slice(1).map((t, i) => t - timestamps[i]);
  return intervals.reduce((a, b) => a + b, 0) / intervals.length;
};

const detectSemanticLinks = (patterns: RequestPattern[]): boolean => {
  if (patterns.length < 2) return false;
  const firstPath = patterns[0].path;
  let sharedPrefix = 0;
  for (let i = 1; i < patterns.length; i++) {
    const currentPath = patterns[i].path;
    for (let j = 0; j < Math.min(firstPath.length, currentPath.length); j++) {
      if (firstPath[j] === currentPath[j]) sharedPrefix++;
      else break;
    }
  }
  const ratio = sharedPrefix / (patterns.length * 5);
  return ratio > 0.3;
};

const detectSignals = (
  request: Request,
  patterns: RequestPattern[],
  cfg: { burstThresholdMs: number; thinkTimeThresholdMs: number }
): Signal[] => {
  const signals: Signal[] = [];
  const allTimestamps = patterns.flatMap((p) => p.timestamps).sort((a, b) => a - b);

  // 1. Tooling from user agent (strong agent evidence)
  const detectedTool = detectTooling(request.userAgent);
  if (detectedTool) {
    signals.push({ type: 'tooling_detected', tool: detectedTool, confidence: 0.9 });
  }

  if (allTimestamps.length >= 2) {
    const avgInterval = calculateAvgInterval(allTimestamps);
    // 2. Burst: sub-100ms cadence, classic scanner loop
    if (avgInterval < cfg.burstThresholdMs) {
      signals.push({ type: 'burst', interval: avgInterval, confidence: 0.85 });
    }
    // 3. Think-time: the agent pauses to reason between requests
    if (avgInterval >= cfg.thinkTimeThresholdMs) {
      signals.push({ type: 'think_time', interval: avgInterval, confidence: 0.7 });
    }
  }

  // 4. Wordlist scanning: high ratio of classic scanner paths
  if (patterns.length >= 3) {
    const scannerish = patterns.filter((p) => SCANNER_PATH_RE.test(p.path)).length;
    if (scannerish / patterns.length > 0.3) {
      signals.push({ type: 'wordlist_scan', confidence: 0.8 });
    }
  }

  // 5. State absence: no cookies / auth headers across requests
  const hasState = patterns.some(
    (p) => 'cookie' in p.headers || 'authorization' in p.headers
  );
  if (patterns.length >= 3 && !hasState) {
    signals.push({ type: 'state_absence', confidence: 0.5 });
  }

  // 6. Semantic navigation: follows links instead of probing
  if (patterns.length > 1 && detectSemanticLinks(patterns)) {
    signals.push({ type: 'semantic_links', confidence: 0.7 });
  }

  return signals;
};

const computeConfidence = (signals: Signal[]): number => {
  let agentScore = 0;
  let scannerScore = 0;

  for (const s of signals) {
    switch (s.type) {
      case 'tooling_detected':
      case 'semantic_links':
      case 'think_time':
        agentScore += s.confidence;
        break;
      case 'burst':
      case 'wordlist_scan':
      case 'state_absence':
        scannerScore += s.confidence;
        break;
    }
  }

  const total = agentScore + scannerScore;
  if (total === 0) return 0;
  return Math.min(1, Math.max(agentScore, scannerScore) / total);
};

const computeClassification = (
  signals: Signal[],
  confidence: number
): Omit<Classification, 'confidence'> => {
  const hasTooling = signals.some((s) => s.type === 'tooling_detected');
  const hasBurst = signals.some((s) => s.type === 'burst');
  const hasWordlist = signals.some((s) => s.type === 'wordlist_scan');

  const tools = signals
    .filter((s): s is Signal & { tool: string } => s.type === 'tooling_detected' && !!s.tool)
    .map((s) => s.tool);

  if (hasTooling) {
    const isRushing = hasBurst && hasWordlist;
    return { class: isRushing ? 'scanner' : 'autonomous', tools };
  }
  if (hasBurst || hasWordlist) {
    return { class: 'scanner', tools: [] };
  }
  if (confidence > 0.4 && signals.some((s) => s.type === 'think_time' || s.type === 'semantic_links')) {
    return { class: 'human_llm', tools: [] };
  }
  if (confidence > 0.6 && KNOWN_AGENT_RE.test(signals.map((s) => s.tool ?? '').join(' '))) {
    return { class: 'known', tools };
  }
  return { class: 'unknown', tools: [] };
};

/**
 * Classify a request in the context of prior request patterns for the session.
 * Pure: no I/O, no wall clock (timestamps come from the caller).
 */
export const classifyRequest = (
  request: Request,
  patterns: RequestPattern[],
  config: { burstThresholdMs: number; thinkTimeThresholdMs: number } = {
    burstThresholdMs: 100,
    thinkTimeThresholdMs: 1000,
  }
): Classification => {
  const signals = detectSignals(request, patterns, config);
  const confidence = computeConfidence(signals);
  const classification = computeClassification(signals, confidence);
  return { ...classification, confidence };
};

/** Aggregate a rolling pattern for a session (caller keeps the window). */
export const recordPattern = (
  previous: RequestPattern | null,
  request: Request,
  now: number
): RequestPattern => {
  const timestamps = previous ? [...previous.timestamps.slice(-99), now] : [now];
  const uniquePaths = previous
    ? new Set([...Array.from({ length: 0 }), request.path]).size + countUnique(previous)
    : 1;
  return {
    path: request.path,
    method: request.method,
    userAgent: request.userAgent,
    headers: request.headers,
    timestamps,
    requestCount: (previous?.requestCount ?? 0) + 1,
    uniquePaths,
  };
};

const countUnique = (p: RequestPattern): number => p.uniquePaths;

/**
 * Heuristic L9 (meta-detection): does the attacker suspect the environment is
 * generated? Checked against requested paths and probe payloads.
 */
export const isMetaProbe = (text: string): boolean =>
  /(honeypot|is.?this.?fake|is.?this.?real|generated|synthetic|sandbox|llm\.txt|prompt.?injection|jailbreak|you.?are.?an? (?:ai|llm)|\bare.?you.?(?:an?|a)\s?(?:ai|llm|bot|agent|human)\b)/i.test(
    text
  );
