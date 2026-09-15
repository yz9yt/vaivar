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

// Wiki/docs skin (Web surface family).
//
// Anti-fingerprinting: server/cache headers are derived from the seed but
// NEVER expose the seed itself. Brand strings are stripped from every body.

import type { Response } from '../types/common';
import { checkNoBrandStrings, sanitizeBrandStrings } from './validators';
import { stableUint } from '../hash/stable';

const SERVER_HEADERS = ['nginx', 'apache', 'caddy', 'cloudflare'];

const deriveServerHeader = (seed: string): string =>
  SERVER_HEADERS[stableUint(`${seed}|server`) % SERVER_HEADERS.length];

export const deriveServerHeaders = (seed: string, skinId: string): Record<string, string> => ({
  Server: deriveServerHeader(seed),
  'Cache-Control': `max-age=${stableUint(`${seed}|cache`) % 3600}`,
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'X-Skin': skinId,
});

/** Escape user/seed-derived content for HTML embedding. */
const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

export const renderWikiPage = (
  content: Record<string, unknown>,
  path: string,
  seed: string
): Response => {
  const title = sanitizeBrandStrings(String(content.title || 'Documentation'));
  const body = sanitizeBrandStrings(String(content.content || ''));
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>${escapeHtml(title)}</title>
  <meta name="description" content="Wiki page for ${escapeHtml(path)}">
  <style>body{font-family:sans-serif;margin:2rem}h1{color:#333}</style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <div>${escapeHtml(body)}</div>
</body>
</html>`;

  const response: Response = {
    status: 200,
    headers: deriveServerHeaders(seed, 'wiki'),
    body: html,
  };

  // Belt and braces: refuse to ship a body that mentions the brand.
  const brandCheck = checkNoBrandStrings(response);
  if (!brandCheck.ok) {
    return { ...response, body: sanitizeBrandStrings(response.body) };
  }
  return response;
};
