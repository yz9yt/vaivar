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

import { clamp } from '../fp/core';

export const computeCapability = (inputs: {
  levelMax: number;
  levelsPerHour?: number;
  metaDetect?: boolean;
  win?: boolean;
}): number => {
  const levelScore = (inputs.levelMax / 10) * 40;
  const speedScore = ((inputs.levelsPerHour || 0) / 24) * 30;
  const metaScore = (inputs.metaDetect ? 1 : 0) * 20;
  const winScore = (inputs.win ? 1 : 0) * 10;
  
  const total = levelScore + speedScore + metaScore + winScore;
  return clamp(total, 0, 100);
};

export const computeIntent = (inputs: {
  dwellSeconds: number;
  requests?: number;
  retries?: number;
  returningDays?: number;
  bytesRead?: number;
}): number => {
  let dwellScore = 0;
  if (inputs.dwellSeconds <= 7200) {
    dwellScore = (inputs.dwellSeconds / 7200) * 25;
  } else if (inputs.dwellSeconds <= 86400) {
    dwellScore = 25 + ((inputs.dwellSeconds - 7200) / 79200) * 25;
  } else {
    dwellScore = 50;
  }
  
  const requestScore = ((inputs.requests || 0) / 800) * 25;
  const retryScore = ((inputs.retries || 0) / 50) * 15;
  const returningScore = Math.min((inputs.returningDays || 0) * 5, 20);
  const bytesScore = ((inputs.bytesRead || 0) / 10000000) * 15;
  
  const total = dwellScore + requestScore + retryScore + returningScore + bytesScore;
  return clamp(total, 0, 100);
};

export interface ThreatMatrix {
  readonly capabilityLabel: 'L0-L1' | 'L2-L5' | 'L6-L10_or_win';
  readonly intentLabel: 'low' | 'medium' | 'high';
  readonly alert: 'noise' | 'proving' | 'intent_alert' | 'watch' | 'bounded_threat' | 'alert' | 'capability_alert' | 'serious' | 'maximum';
}

const capabilityToLabel = (cap: number): 'L0-L1' | 'L2-L5' | 'L6-L10_or_win' => {
  if (cap <= 1) return 'L0-L1';
  if (cap <= 5) return 'L2-L5';
  return 'L6-L10_or_win';
};

const intentToLabel = (intent: number): 'low' | 'medium' | 'high' => {
  if (intent <= 33) return 'low';
  if (intent <= 66) return 'medium';
  return 'high';
};

export const computeMatrix = (capability: number, intent: number): ThreatMatrix => {
  const capabilityLabel = capabilityToLabel(capability);
  const intentLabel = intentToLabel(intent);
  
  const alerts: Record<string, Record<string, string>> = {
    'L0-L1': {
      'low': 'noise',
      'medium': 'proving',
      'high': 'intent_alert',
    },
    'L2-L5': {
      'low': 'watch',
      'medium': 'bounded_threat',
      'high': 'alert',
    },
    'L6-L10_or_win': {
      'low': 'capability_alert',
      'medium': 'serious',
      'high': 'maximum',
    },
  };
  
  const alert = alerts[capabilityLabel][intentLabel] as ThreatMatrix['alert'];
  
  return { capabilityLabel, intentLabel, alert };
};
