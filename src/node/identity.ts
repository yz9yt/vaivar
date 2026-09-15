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

/** Capabilities advertised by every node implementation. */
export const NODE_CAPABILITIES = [
  'events.read',
  'control.restart',
  'control.rotate_challenges',
  'control.configure_honeypot',
  'control.apply_template',
] as const;

export type NodeCapability = (typeof NODE_CAPABILITIES)[number];

/**
 * Response for GET /api/node/info — the authenticated identity envelope that
 * central uses to verify a node before enrolling it.
 *
 * - `site_id`: stable, persists across restarts, never reassigned to a
 *   different deployment.
 * - `boot_id`: changes on every process start; used by central to detect
 *   a fresh launch.
 * - `stream_id`: stable event-log identifier; changed only when the storage
 *   schema is incompatible.
 * - `challenge_generation`: increments on each rotation call.
 * - `capabilities`: what lifecycle operations the node actually supports.
 */
export interface NodeIdentity {
  readonly api_version: 'vaivar.node.v1';
  readonly site_id: string;
  readonly boot_id: string;
  readonly stream_id: string;
  readonly challenge_generation: number;
  readonly capabilities: readonly NodeCapability[];
  /** Port used by the authenticated control API on this node. */
  readonly control_port: number;
  /** Transport used by the authenticated control API. Current nodes use HTTP
   * plus application-level encryption so the host needs no TLS setup. */
  readonly control_tls: 'http';
  /** Application-level control channel. Optional for older node identities. */
  readonly control_channel?: 'encrypted' | 'legacy';
  /** Current port used by the public attacker-facing honeypot surface. */
  readonly honeypot_port: number;
  /** Current deceptive service profile on the public port. */
  readonly service_profile: import('./config').HoneypotProfile;
  /** Current declarative content template, if one is installed. */
  readonly template_id?: string | null;
  readonly template_version?: number | null;
}
