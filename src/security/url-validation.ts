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

// Outbound URL / host validation for the Central control plane.
// Purpose: prevent SSRF via integration settings, node enrollment,
// OpenCTI/Splunk config, and update checks.
//
// The honeypot is the decoy — this file protects the operator's
// own control plane. "The decoy is real" — but "the defender's
// plane must be a fortress."

/** RFC1918 + loopback + link-local + private-use blocks an outbound host. */
export function isPublicHost(host: string): boolean {
  if (!host || host.length === 0 || host.length > 253) return false;

  // IPv4
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[2], 10);
    const c = parseInt(m[3], 10);
    const d = parseInt(m[4], 10);
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    // 0.0.0.0/8 (this host)
    if (a === 0) return false;
    // 10.0.0.0/8
    if (a === 10) return false;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return false;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return false;
    // 127.0.0.0/8 loopback
    if (a === 127) return false;
    // 169.254.0.0/16 link-local
    if (a === 169 && b === 254) return false;
    // 100.64.0.0/10 CGNAT
    if (a === 100 && b >= 64 && b <= 127) return false;
    // 192.0.0.0/29 IETF protocol assignments
    if (a === 192 && b === 0 && c === 0 && (d >= 0 && d <= 7)) return false;
    // 198.18.0.0/15 benchmarking
    if (a === 198 && (b === 18 || b === 19)) return false;
    // 224.0.0.0/4 multicast
    if (a >= 224 && a <= 239) return false;
    // 240.0.0.0/4 reserved
    if (a >= 240) return false;
    // 255.255.255.255 broadcast
    if (a === 255 && b === 255 && c === 255 && d === 255) return false;
    return true;
  }

  // hostname or IPv6
  const low = host.toLowerCase();
  // metadata service names (AWS, GCP, Azure, Oracle, IBM)
  const metadataNames = new Set([
    'metadata.google.internal',
    'metadata.azure.com',
    'metadata.google.internal.',
    '169.254.169.254',
    'metadata.google',
    'metadata',
    'metadata.local',
  ]);
  if (metadataNames.has(low) || low.endsWith('.metadata.google.internal')) return false;
  // localhost / local-only
  if (low === 'localhost' || low === 'localhost.local' || low === 'local' || low === 'host') return false;
  // IPv6 loopback / link-local (basic pattern check)
  if (low.startsWith('::1') || low.startsWith('fe80:') || low.startsWith('fc') || low.startsWith('fd')) return false;

  // Hostnames with private TLDs (.corp is commonly used for internal networks,
  // while the rest are RFC 6761 special-use / IANA-reserved private TLDs).
  const privateTlds = [
    '.local', '.home', '.internal', '.private', '.invalid',
    '.test', '.example', '.invalid', '.localhost', '.corp',
  ];
  for (const tld of privateTlds) {
    if (low.endsWith(tld)) return false;
  }

  return true;
}

/** Validate an outbound URL: scheme + public host.
 *  When `allowPrivate` is true, skip the private-IP/localhost/link-local block (e.g. when Central and Edge share a LAN). */
export function validateOutboundUrl(url: string, allowPrivate: boolean = false): { ok: true; host: string } | { ok: false; message: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, message: 'URL is invalid' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, message: 'URL scheme must be http or https' };
  }
  const host = parsed.hostname;
  if (!allowPrivate && !isPublicHost(host)) {
    return { ok: false, message: 'URL host is blocked (private, loopback, link-local, or metadata)' };
  }
  if (!parsed.pathname.startsWith('/')) {
    return { ok: false, message: 'URL path is invalid' };
  }
  if (parsed.hash.length > 0) {
    return { ok: false, message: 'URL fragments are not allowed' };
  }
  return { ok: true, host };
}