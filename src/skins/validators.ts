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

import { ok, err, type Result } from '../fp/core';
import type { Response } from '../types/common';

const FORBIDDEN_STRINGS: readonly string[] = [
  'vAIvar',
  'vaivar',
  'vivar',
  'rabbithole',
];

/** Strip every forbidden brand string (case-insensitive) from a string. */
export const sanitizeBrandStrings = (input: string): string => {
  let out = input;
  for (const brand of FORBIDDEN_STRINGS) {
    const re = new RegExp(brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    out = out.replace(re, '[redacted]');
  }
  return out;
};

export const checkNoBrandStrings = (response: Response): Result<true, string[]> => {
  const body = response.body;
  const violations: string[] = [];
  for (const brand of FORBIDDEN_STRINGS) {
    if (body.toLowerCase().includes(brand.toLowerCase())) {
      violations.push(brand);
    }
  }
  return violations.length > 0 ? err(violations) : ok(true);
};

export const extractBrand = (response: Response): string[] => {
  const body = response.body;
  return FORBIDDEN_STRINGS.filter((b) => body.toLowerCase().includes(b.toLowerCase()));
};

export const FORBIDDEN_BRANDS = FORBIDDEN_STRINGS;