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

// Central node registry: verifiable, encrypted storage of node
// registrations. A node cannot self-register — central must call
// the node's /api/node/info endpoint to verify the identity before
// enrolling it. Roles (admin, reader) are assigned here and never
// stored in the node itself.

import type { StorageIndexer } from '../storage/indexer';
import type { CentralNodeRecord, CentralNodeCapability } from '../storage/types';
import { type NodeCapability } from '../node/identity';
import {
  deriveKey,
  encryptSecret,
  decryptSecret,
  tokenFingerprint,
} from './secret-store';
import { type NodeClient, type NodeClientError, type NodeIdentityResponse } from './node-client';
import type { HoneypotProfile } from '../node/config';

export interface NodeRegistrationRequest {
  /** Hostname or IP as the node presents it (no URL scheme, no path). */
  readonly host: string;
  readonly port: number;
  readonly token: string;
  /** Socket transport. Honeypot control sockets use HTTP plus encrypted RPC. */
  readonly tls?: 'http';
  /** Application-level control channel. New deployments use encrypted. */
  readonly channel?: 'encrypted' | 'legacy';
}

export interface NodeEnrollmentResult {
  readonly registered: boolean;
  readonly site_id: string;
  readonly tls: 'http';
  readonly channel: 'encrypted' | 'legacy';
  readonly token_fingerprint: string;
  readonly capabilities: readonly NodeCapability[];
  readonly honeypot_port?: number;
  readonly service_profile?: string;
  readonly template_id?: string | null;
  readonly template_version?: number | null;
}

export type PreviewCode = 'unreachable' | 'auth' | 'encryption' | 'incompatible' | 'invalid';

export type PreviewResult =
  | { ok: true; identity: NodeIdentityResponse; duplicate: boolean }
  | { ok: false; code: PreviewCode; message: string };

export class DuplicateNodeError extends Error {
  readonly code: 'duplicate' | 'duplicate_endpoint';
  readonly existing_site_id: string;
  constructor(existing_site_id: string, code: 'duplicate' | 'duplicate_endpoint' = 'duplicate') {
    super('duplicate');
    this.name = 'DuplicateNodeError';
    this.code = code;
    this.existing_site_id = existing_site_id;
  }
}

export interface CentralNodeRecordWithSecret {
  readonly site_id: string;
  readonly host: string;
  readonly port: number;
  readonly honeypot_port?: number | null;
  readonly service_profile?: HoneypotProfile | string | null;
  readonly template_id?: string | null;
  readonly template_version?: number | null;
  readonly encrypted_secret: string;
  readonly iv: string;
  readonly auth_tag: string;
  readonly encrypted_secret_aad: string;
  readonly token_fingerprint: string;
  readonly capabilities: string[];
  readonly registered_at_ms: number;
  readonly last_contacted_at_ms: number | null;
  readonly tls?: 'http';
  readonly channel?: 'encrypted' | 'legacy';
}

/**
 * Create a node registry that stores encrypted node credentials
 * backed by the central storage indexer.
 */
export const createNodeRegistry = (
  storage: StorageIndexer,
  centralKey: string,
  nodeClient: NodeClient
): NodeRegistry => {
  const key = deriveKey(centralKey, 'central-nodes');

  const mapPreviewError = (err: NodeClientError): PreviewCode => {
    if (err.kind === 'connection' || err.kind === 'timeout') return 'unreachable';
    if (err.kind === 'auth') return 'auth';
    if (err.kind === 'not_found' || err.kind === 'invalid_response') return 'invalid';
    const msg = err.message || '';
    if (err.kind === 'unknown' && (msg.includes('aborted') || msg.includes('AbortError'))) return 'unreachable';
    return 'invalid';
  };

  const previewIdentity = async (req: NodeRegistrationRequest): Promise<PreviewResult> => {
    const endpoint = {
      host: req.host,
      port: req.port,
      token: req.token,
      tls: req.tls ?? 'http',
      channel: req.channel ?? 'encrypted',
    };
    const result = await nodeClient.fetchIdentity(endpoint);
    if ('kind' in result) {
      const code = mapPreviewError(result);
      return { ok: false, code, message: result.message };
    }
    const identity = result as NodeIdentityResponse;
    if (identity.api_version !== 'vaivar.node.v1') {
      return { ok: false, code: 'incompatible', message: 'Node API version is not vaivar.node.v1' };
    }
    if (endpoint.channel === 'encrypted' && identity.control_channel !== 'encrypted') {
      return { ok: false, code: 'encryption', message: 'The node does not advertise the encrypted application control channel' };
    }
    const existing = await storage.getCentralNode(identity.site_id);
    return { ok: true, identity, duplicate: existing !== null };
  };

  return {
    previewIdentity,

    /**
     * Verify a node's identity by calling /api/node/info, then
     * register it with an encrypted secret store. Returns null if
     * the node cannot be verified (wrong token, unreachable, etc.).
     * Throws DuplicateNodeError if site_id or host:port already exists.
     * Does not stamp last_contacted_at_ms — first successful poll does.
     */
    async enroll(req: NodeRegistrationRequest): Promise<NodeEnrollmentResult | null> {
      const preview = await previewIdentity(req);
      if (!preview.ok) return null;
      const identity = preview.identity;

      const siteId = identity.site_id;
      if (preview.duplicate) {
        throw new DuplicateNodeError(siteId, 'duplicate');
      }
      const sameEndpoint = (await storage.listCentralNodes()).find(
        (n) => n.host === req.host && n.port === req.port
      );
      if (sameEndpoint) {
        throw new DuplicateNodeError(sameEndpoint.site_id, 'duplicate_endpoint');
      }

      const encAad = `node:${siteId}`;
      const encrypted = encryptSecret(key, req.token, encAad);
      const fp = tokenFingerprint(req.token);

      const now = Date.now();
      await storage.saveCentralNode({
        site_id: siteId,
        host: req.host,
        port: req.port,
        honeypot_port: identity.honeypot_port ?? null,
        service_profile: identity.service_profile ?? null,
        template_id: identity.template_id ?? null,
        template_version: identity.template_version ?? null,
        encrypted_secret: encrypted.ciphertext,
        iv: encrypted.iv,
        auth_tag: encrypted.tag,
        encrypted_secret_aad: encAad,
        token_fingerprint: fp,
        capabilities: identity.capabilities as CentralNodeCapability[],
        tls: req.tls ?? 'http',
        channel: req.channel ?? 'encrypted',
        registered_at_ms: now,
        last_contacted_at_ms: null,
      });

      return {
        registered: true,
        site_id: siteId,
        tls: req.tls ?? 'http',
        channel: req.channel ?? 'encrypted',
        token_fingerprint: fp,
        capabilities: identity.capabilities as NodeCapability[],
        honeypot_port: identity.honeypot_port,
        service_profile: identity.service_profile,
        template_id: identity.template_id,
        template_version: identity.template_version,
      };
    },

    /** List all registered nodes without exposing any secrets. */
    async listNodes(): Promise<CentralNodeRecord[]> {
      return storage.listCentralNodes();
    },

    /** Get a node by site_id, or null if not found. */
    async getNode(siteId: string): Promise<CentralNodeRecord | null> {
      return storage.getCentralNode(siteId);
    },

    /** Update only runtime metadata learned from the node identity. */
    async updateNodeRuntime(siteId: string, runtime: { honeypot_port?: number | null; service_profile?: string | null; template_id?: string | null; template_version?: number | null; capabilities?: string[] }): Promise<boolean> {
      const node = await storage.getCentralNode(siteId);
      if (!node) return false;
      await storage.saveCentralNode({
        ...node,
        honeypot_port: runtime.honeypot_port ?? node.honeypot_port ?? null,
        service_profile: runtime.service_profile ?? node.service_profile ?? null,
        template_id: runtime.template_id ?? node.template_id ?? null,
        template_version: runtime.template_version ?? node.template_version ?? null,
        capabilities: (runtime.capabilities as CentralNodeCapability[] | undefined) ?? node.capabilities,
      });
      return true;
    },

    /** Update operator metadata (custom name, notes). */
    async updateNodeMetadata(siteId: string, metadata: { name?: string | null; notes?: string | null }): Promise<boolean> {
      return storage.updateCentralNodeMetadata(siteId, metadata);
    },

    /**
     * Verify new settings/token before activating a pending change.
     * Calls the node's /api/node/info to confirm the new token
     * produces the same identity. Returns the verified identity
     * or null if the node rejects the new token.
     */
    async verifySettings(siteId: string, newToken: string, requestedChannel?: 'encrypted' | 'legacy'): Promise<NodeIdentityResponse | null> {
      const node = await storage.getCentralNode(siteId);
      if (!node) return null;
      const channel = requestedChannel ?? node.channel ?? 'legacy';

      const endpoint = {
        host: node.host,
        port: node.port,
        token: newToken,
        tls: node.tls ?? 'http',
        channel,
      };
      const result = await nodeClient.fetchIdentity(endpoint);
      if ('kind' in result) return null;
      const identity = result as NodeIdentityResponse;
      if (channel === 'encrypted' && identity.control_channel !== 'encrypted') return null;
      return identity.api_version === 'vaivar.node.v1' ? identity : null;
    },

    /** Activate a verified pending token change for a node. */
    async activateNode(siteId: string, newToken: string, requestedChannel?: 'encrypted' | 'legacy'): Promise<boolean> {
      const identity = await this.verifySettings(siteId, newToken, requestedChannel);
      if (!identity) return false;
      const node = await storage.getCentralNode(siteId);
      if (!node) return false;

      const aad = `node:${siteId}`;
      const encrypted = encryptSecret(key, newToken, aad);
      await storage.saveCentralNode({
        ...node,
        encrypted_secret: encrypted.ciphertext,
        iv: encrypted.iv,
        auth_tag: encrypted.tag,
        encrypted_secret_aad: aad,
        token_fingerprint: tokenFingerprint(newToken),
        channel: requestedChannel ?? node.channel ?? 'legacy',
        honeypot_port: identity.honeypot_port ?? node.honeypot_port ?? null,
        service_profile: identity.service_profile ?? node.service_profile ?? null,
        template_id: identity.template_id ?? node.template_id ?? null,
        template_version: identity.template_version ?? node.template_version ?? null,
        capabilities: identity.capabilities as CentralNodeCapability[],
      });
      return true;
    },

    /** Remove a node from the registry. */
    async removeNode(siteId: string): Promise<void> {
      // Delete via storage — not exposed through any API endpoint.
      if (!storage['db']) return;
      try {
        storage['db'].prepare('DELETE FROM central_nodes WHERE site_id = ?').run(siteId);
      } catch {
        // Non-fatal.
      }
    },

    /**
     * Decrypt the stored barrier token for a node. Returns null when
     * decryption fails (wrong key or tampered record). Used only by
     * the central poller and admin operations; never exposed over HTTP.
     */
    async decryptToken(siteId: string): Promise<string | null> {
      const node = await storage.getCentralNode(siteId);
      if (!node) return null;
      try {
        return decryptSecret(key, {
          version: 'secret.v1',
          ciphertext: node.encrypted_secret,
          iv: node.iv,
          tag: node.auth_tag,
        }, node.encrypted_secret_aad);
      } catch {
        return null;
      }
    },

  };
};

export interface NodeRegistry {
  previewIdentity(req: NodeRegistrationRequest): Promise<PreviewResult>;
  enroll(req: NodeRegistrationRequest): Promise<NodeEnrollmentResult | null>;
  listNodes(): Promise<CentralNodeRecord[]>;
  getNode(siteId: string): Promise<CentralNodeRecord | null>;
  updateNodeRuntime(siteId: string, runtime: { honeypot_port?: number | null; service_profile?: string | null; template_id?: string | null; template_version?: number | null; capabilities?: string[] }): Promise<boolean>;
  updateNodeMetadata(siteId: string, metadata: { name?: string | null; notes?: string | null }): Promise<boolean>;
  verifySettings(siteId: string, newToken: string, requestedChannel?: 'encrypted' | 'legacy'): Promise<NodeIdentityResponse | null>;
  activateNode(siteId: string, newToken: string, requestedChannel?: 'encrypted' | 'legacy'): Promise<boolean>;
  removeNode(siteId: string): Promise<void>;
  decryptToken(siteId: string): Promise<string | null>;
}
