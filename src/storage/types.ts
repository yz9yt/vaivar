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

// vAIvar Storage Types
// Database abstraction for sessions, events, and flags

import type { HoneypotProfile, HoneypotRuntimeConfig } from '../node/config';
import type { HoneypotTemplate } from '../templates/types';

export interface SessionRecord {
  readonly session_id: string;
  readonly seed_id: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly state_json: string;
  readonly site_id?: string;
}

export interface EventRecord {
  readonly id: string;
  readonly session_id: string;
  readonly site_id?: string | null;
  readonly ts: number;
  readonly event_type: 'session.upsert' | 'flag.hit';
  readonly payload_json: string;
}

export interface FlagRecord {
  readonly session_id: string;
  readonly flag_code: string;
  readonly flag_level: number | null;
  readonly node_id: string;
  readonly created_at: number;
  readonly site_id?: string;
}

export interface AttackerActivityRecord {
  readonly id: string;
  readonly session_id: string;
  readonly site_id?: string | null;
  readonly ts: number;
  readonly event_type: string;
  readonly ip: string | null;
  readonly user_agent: string;
  readonly path: string | null;
  readonly classification: string | null;
  readonly confidence: number | null;
  readonly tooling: string | null;
  readonly level_max: number | null;
  readonly flags_fired: string | null;
  readonly win_isolated: boolean | null;
  readonly meta_detect: boolean | null;
  readonly capability: number | null;
  readonly intent: number | null;
  readonly severity: string | null;
  readonly payload_json: string;
}

export interface StorageStats {
  readonly sessions: number;
  readonly events: number;
  readonly flags: number;
  readonly attacker_activity: number;
  readonly event_envelopes: number;
  readonly size_bytes: number;
}

export interface StorageConfig {
  readonly path: string;
  readonly encryptionKey?: string;
  readonly retentionDays?: number;
}

/**
 * RBAC account. `token_hash` is
 * HMAC(centralKey, token) — plaintext tokens are never persisted.
 */
export interface AccountRecord {
  readonly id: string;
  readonly name: string;
  readonly role: string; // validated by rbac.isRole in the server layer
  readonly token_hash: string;
  readonly created_by: string;
  readonly created_at: number;
}

/** Record of a registered central node (opaque host: the node decides). */
export type CentralNodeCapability = 'events.read' | 'control.restart' | 'control.rotate_challenges' | 'control.configure_honeypot' | 'control.apply_template';

export interface CentralNodeRecord {
  readonly site_id: string;
  readonly host: string;
  /** Authenticated control API port (legacy field name retained). */
  readonly port: number;
  /** Public attacker-facing port reported by the node. */
  readonly honeypot_port?: number | null;
  /** Public service profile reported by the node. */
  readonly service_profile?: HoneypotProfile | string | null;
  /** Current declarative public template reported by the node. */
  readonly template_id?: string | null;
  readonly template_version?: number | null;
  /** Operator-assigned descriptive name for the honeypot. */
  readonly name?: string | null;
  /** Operator notes and context regarding the honeypot deployment. */
  readonly notes?: string | null;
  readonly encrypted_secret: string;
  readonly iv: string;
  readonly auth_tag: string;
  readonly encrypted_secret_aad: string;
  readonly token_fingerprint: string;
  readonly capabilities: CentralNodeCapability[];
  readonly registered_at_ms: number;
  readonly last_contacted_at_ms: number | null;
  /** Honeypot control transport is always plain HTTP; payloads use encrypted RPC. */
  readonly tls?: 'http';
  /** Application-level control channel. New deployments use encrypted. */
  readonly channel?: 'encrypted' | 'legacy';
}

/** Versioned template catalog entry kept by the central plane. */
export interface CentralTemplateRecord {
  readonly id: string;
  readonly version: number;
  readonly profile: HoneypotProfile;
  readonly name: string;
  readonly description: string;
  readonly template_json: string;
  readonly created_at_ms: number;
  readonly updated_at_ms: number;
}

/** Short-lived capability used only for a first, one-time node bootstrap. */
export interface BootstrapTokenMetadata {
  readonly host?: string;
  readonly control_port?: number;
  readonly honeypot_port?: number;
  readonly profile?: HoneypotProfile;
  readonly template_id?: string;
  readonly install_dir?: string;
  readonly compose_project?: string;
  readonly site_id?: string;
}

export type { HoneypotProfile, HoneypotRuntimeConfig, HoneypotTemplate };

/** Delivery progress for one external destination (e.g. Splunk HEC). */
export interface ExportDeliveryRecord {
  readonly destination: string;
  readonly last_sequence: string | null;
  readonly sent_count: number;
  readonly failed_count: number;
  readonly last_error: string | null;
  readonly last_attempt_at_ms: number | null;
}

/** Integration kind handled by the central plane. */
export type IntegrationKind = 'cti' | 'siem' | 'topology' | 'metrics' | 'dashboard';

/**
 * Persisted configuration for one third-party integration (OpenCTI, Splunk,
 * Prometheus/Grafana, ...). Secrets (tokens/passwords) are stored encrypted
 * on the server and are never returned to the browser; a blank field in an
 * update means "keep the existing value".
 *
 * Revision model: a draft is
 * edited and tested; only a verified revision can be promoted to active. When
 * the integration is disabled the active revision remains valid but idle, so
 * re-enabling restores the last good configuration.
 */
export interface IntegrationSetting {
  /** Stable platform id, e.g. 'opencti', 'splunk', 'prometheus', 'grafana'. */
  readonly name: string;
  readonly kind: IntegrationKind;
  /** Human-readable platform label. */
  readonly label: string;
  /** Active JSON payload (field set, no secrets in cleartext). */
  readonly config_json: string;
  readonly enabled: number;
  /** When the current active revision was last connection-verified (ms). */
  readonly verified_at_ms: number | null;
  /** When the last connection test ran (ms). */
  readonly tested_at_ms: number | null;
  readonly last_error: string | null;
  readonly updated_at_ms: number;
}
