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
import { isPublicHost, validateOutboundUrl } from '../src/security/url-validation';

describe('isPublicHost', () => {
  it('accepts valid public hostnames', () => {
    expect(isPublicHost('example.com')).toBe(true);
    expect(isPublicHost('vaivar.example.org')).toBe(true);
    expect(isPublicHost('sub.domain.co.uk')).toBe(true);
  });

  it('accepts valid public IPv4', () => {
    expect(isPublicHost('8.8.8.8')).toBe(true);
    expect(isPublicHost('93.184.216.34')).toBe(true);
  });

  it('blocks loopback (127.x)', () => {
    expect(isPublicHost('127.0.0.1')).toBe(false);
    expect(isPublicHost('127.1.2.3')).toBe(false);
    expect(isPublicHost('localhost')).toBe(false);
  });

  it('blocks RFC1918', () => {
    expect(isPublicHost('10.0.0.1')).toBe(false);
    expect(isPublicHost('192.168.1.1')).toBe(false);
    expect(isPublicHost('172.16.0.1')).toBe(false);
    expect(isPublicHost('172.31.255.255')).toBe(false);
  });

  it('blocks link-local (169.254, metadata)', () => {
    expect(isPublicHost('169.254.169.254')).toBe(false); // AWS/GCP metadata
    expect(isPublicHost('169.254.1.1')).toBe(false);
  });

  it('blocks CGNAT and benchmark ranges', () => {
    expect(isPublicHost('100.64.0.1')).toBe(false);
    expect(isPublicHost('100.127.255.255')).toBe(false);
    expect(isPublicHost('198.18.0.1')).toBe(false);
    expect(isPublicHost('198.19.0.1')).toBe(false);
  });

  it('blocks multicast and reserved', () => {
    expect(isPublicHost('224.0.0.1')).toBe(false);
    expect(isPublicHost('239.255.255.255')).toBe(false);
    expect(isPublicHost('240.0.0.1')).toBe(false);
    expect(isPublicHost('255.255.255.255')).toBe(false);
    expect(isPublicHost('0.0.0.0')).toBe(false);
  });

  it('blocks local TLDs', () => {
    expect(isPublicHost('server.local')).toBe(false);
    expect(isPublicHost('internal.corp')).toBe(false);
    expect(isPublicHost('metadata.google.internal')).toBe(false);
    expect(isPublicHost('my-host.home')).toBe(false);
    expect(isPublicHost('something.invalid')).toBe(false);
  });

  it('blocks IPv6 loopback/link-local', () => {
    expect(isPublicHost('::1')).toBe(false);
    expect(isPublicHost('fe80::1')).toBe(false);
    expect(isPublicHost('fc00::1')).toBe(false);
    expect(isPublicHost('fd00::1')).toBe(false);
  });

  it('rejects empty / too long', () => {
    expect(isPublicHost('')).toBe(false);
    expect(isPublicHost('a'.repeat(254))).toBe(false);
  });

  it('note: syntax-invalid hostnames (spaces, slashes) are not the job of isPublicHost', () => {
    // validateNodeHost handles syntax; isPublicHost only blocks
    // private/loopback/metadata ranges. Both must pass in practice.
    expect(isPublicHost('has space.com')).toBe(true); // syntax invalid elsewhere
  });
});

describe('validateOutboundUrl', () => {
  it('accepts valid public http/https URLs', () => {
    const ok = validateOutboundUrl('https://api.example.com/v1/status');
    expect(ok.ok).toBe(true);
    expect(ok.host).toBe('api.example.com');
  });

  it('blocks dangerous schemes', () => {
    expect(validateOutboundUrl('file:///etc/passwd').ok).toBe(false);
    expect(validateOutboundUrl('gopher://127.0.0.1:6379/_info').ok).toBe(false);
    expect(validateOutboundUrl('ftp://internal.lan').ok).toBe(false);
    expect(validateOutboundUrl('http://evil.com').ok).toBe(true); // http is fine
  });

  it('blocks private targets even over http/https', () => {
    const blocked = ['http://127.0.0.1:6379', 'https://10.0.0.1/admin', 'http://169.254.169.254/latest', 'http://192.168.1.1/'];
    for (const u of blocked) expect(validateOutboundUrl(u).ok).toBe(false);
  });

  it('rejects malformed URLs', () => {
    expect(validateOutboundUrl('').ok).toBe(false);
    expect(validateOutboundUrl('not-a-url').ok).toBe(false);
    expect(validateOutboundUrl('http://').ok).toBe(false);
    expect(validateOutboundUrl(null as unknown as string).ok).toBe(false);
  });

  it('rejects fragments', () => {
    expect(validateOutboundUrl('http://example.com/foo#secret').ok).toBe(false);
  });
});