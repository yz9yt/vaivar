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

import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * Resolves the application version dynamically from package.json,
 * falling back deterministically to '1.0.0'.
 */
function resolveVersion(): string {
  const candidates = [
    join(__dirname, '..', 'package.json'),      // from dist/ or src/
    join(__dirname, '..', '..', 'package.json'),// from nested build directories
    join(process.cwd(), 'package.json'),        // current working directory
  ];

  for (const candidate of candidates) {
    try {
      const content = readFileSync(candidate, 'utf8');
      const parsed = JSON.parse(content);
      if (typeof parsed.version === 'string' && parsed.version.trim().length > 0) {
        return parsed.version.trim();
      }
    } catch {
      // Continue to next candidate
    }
  }

  return '1.0.0';
}

export const VAIVAR_VERSION = resolveVersion();
export const VAIVAR_NAME = 'vAIvar Central Command';
export const VAIVAR_CODENAME = 'Autonomous Deception Matrix';
export const VAIVAR_SPEC_VERSION = 'vaivar.event.v2';
