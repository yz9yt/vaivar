/**
 * vAIvar - Shared application branding.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const VAIVAR_CREATOR_CREDIT = 'created by @yz9yt';
export const VAIVAR_CREATOR_URL = 'https://x.com/yz9yt';
export const VAIVAR_LICENSE_URL = 'https://www.apache.org/licenses/LICENSE-2.0';
export const VAIVAR_LOGO_URL = '/assets/vaivar_logo.svg';

let cachedLogoSvg: string | null | undefined;

/**
 * Resolve the checked-in logo from both source (tsx) and compiled (dist)
 * layouts. The content is cached because it is served for every page load.
 */
export function readVaivarLogoSvg(): string | null {
  if (cachedLogoSvg !== undefined) return cachedLogoSvg;

  const candidates = [
    join(__dirname, '..', 'logos', 'vaivar_logo.svg'),
    join(__dirname, '..', '..', 'logos', 'vaivar_logo.svg'),
    join(process.cwd(), 'logos', 'vaivar_logo.svg'),
  ];

  for (const candidate of candidates) {
    try {
      const logo = readFileSync(candidate, 'utf8');
      if (logo.trim().length > 0) {
        cachedLogoSvg = logo;
        return logo;
      }
    } catch {
      // Try the next layout-specific candidate.
    }
  }

  cachedLogoSvg = null;
  return cachedLogoSvg;
}
