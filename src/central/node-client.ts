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

// Client for calling registered node APIs. Used exclusively by the central
// plane to poll node status, read events, and send commands. The client
// enforces safety boundaries: no redirect following, HTTP-only transport,
// application-encrypted control payloads, timeout and size limits, typed
// errors for downstream diagnostics.

import { randomUUID } from 'node:crypto';
import { request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions as HttpRequestOptions } from 'node:http';
import type { HoneypotProfile } from '../node/config';
import {
  deriveControlKey,
  openControlMessage,
  sealControlMessage,
  type ControlRequest,
  type ControlResponse,
} from '../security/control-channel';

export const NODE_API_VERSION = 'vaivar.node.v1';
export const DEFAULT_NODE_TIMEOUT_MS = 15_000;
export const DEFAULT_MAX_PAGE_SIZE = 500;

export interface NodeEndpoint {
  readonly host: string;
  readonly port: number;
  readonly token: string;
  /** The control socket is intentionally plain HTTP; confidentiality lives in the envelope. */
  readonly tls?: 'http';
  /** Application channel; omitted values default to encrypted control RPC. */
  readonly channel?: 'encrypted' | 'legacy';
}

export interface NodeIdentityResponse {
  api_version: string;
  site_id: string;
  boot_id: string;
  stream_id: string;
  challenge_generation: number;
  capabilities: string[];
  /** Optional so Central can still read identities from older nodes. */
  control_port?: number;
  honeypot_port?: number;
  service_profile?: HoneypotProfile | string;
  template_id?: string | null;
  template_version?: number | null;
  /** Transport used by the node control API. Optional for older nodes. */
  control_tls?: 'http';
  /** Application-level channel used by current nodes. */
  control_channel?: 'encrypted' | 'legacy';
}

export interface EventPage {
  spec: string;
  site_id: string;
  stream_id: string;
  events: Array<{ event_id: string; sequence: string; payload: unknown }>;
  next_cursor: string | null;
  high_watermark: string;
  has_more: boolean;
}

export interface NodeCommandResponse {
  command_id: string;
  type: string;
  executed: boolean;
  outcome: unknown;
}

export interface NodeClientError {
  readonly kind: 'timeout' | 'connection' | 'auth' | 'not_found' | 'invalid_response' | 'unknown';
  readonly message: string;
  readonly status?: number;
}

const toError = (e: unknown): NodeClientError => {
  if (e instanceof Error) {
    const code = (e as Error & { code?: string }).code;
    const status = (e as Error & { status?: number }).status;
    if (e.name === 'AbortError' || code === 'ETIMEDOUT' || e.message.includes('aborted') || e.message.includes('ETIMEDOUT') || e.message.includes('timed out')) {
      return { kind: 'timeout', message: e.message };
    }
    if (status === 401 || status === 403 || e.message.includes('401') || e.message.includes('403')) {
      return { kind: 'auth', message: e.message, status: status ?? 401 };
    }
    if (status === 404) return { kind: 'not_found', message: e.message, status: 404 };
    if (e.message.includes('ECONNREFUSED')) return { kind: 'connection', message: e.message };
  }
  return { kind: 'unknown', message: String(e) };
};

interface RawNodeResponse {
  readonly status: number;
  readonly body: string;
}

const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

const requestNode = (
  endpoint: NodeEndpoint,
  requestPath: string,
  method: 'GET' | 'POST',
  body: string | undefined,
  timeoutMs: number,
  withBearer = true,
): Promise<RawNodeResponse> => new Promise((resolve, reject) => {
  const host = endpoint.host.replace(/^https?:\/\//, '');

  let request: ClientRequest | undefined;
  let settled = false;
  const fail = (error: Error): void => {
    if (settled) return;
    settled = true;
    request?.destroy();
    reject(error);
  };
  const complete = (response: RawNodeResponse): void => {
    if (settled) return;
    settled = true;
    resolve(response);
  };
  const handleResponse = (response: IncomingMessage): void => {
    let size = 0;
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk: string) => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_RESPONSE_BYTES) {
        response.destroy();
        fail(new Error('Node response exceeded the maximum size'));
        return;
      }
      text += chunk;
    });
    response.on('end', () => complete({ status: response.statusCode ?? 0, body: text }));
    response.on('error', fail);
  };

  const headers: Record<string, string> = { Accept: 'application/json' };
  if (withBearer) headers.Authorization = `Bearer ${endpoint.token}`;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(Buffer.byteLength(body));
  }
  const commonOptions = {
    hostname: host,
    port: endpoint.port,
    path: requestPath,
    method,
    headers,
    agent: false,
    timeout: timeoutMs,
  };

  request = httpRequest(commonOptions as HttpRequestOptions, handleResponse);
  request.once('error', fail);
  request.setTimeout(timeoutMs, () => fail(Object.assign(new Error('Node request timed out'), { code: 'ETIMEDOUT' })));

  const endRequest = (): void => {
    if (!request || settled) return;
    if (body === undefined) request.end();
    else request.end(body);
  };

  endRequest();
});

const parseNodeResponse = <T>(response: RawNodeResponse): T => {
  if (response.status < 200 || response.status >= 300) {
    throw Object.assign(new Error(`HTTP ${response.status}: ${response.body.slice(0, 500)}`), { status: response.status });
  }
  try {
    return JSON.parse(response.body) as T;
  } catch {
    throw new Error('Node returned invalid JSON');
  }
};

const requestControl = async (
  endpoint: NodeEndpoint,
  controlRequest: ControlRequest,
  timeoutMs: number,
): Promise<RawNodeResponse> => {
  // Explicit legacy mode exists only for nodes deployed before the encrypted
  // channel was introduced. New endpoints default to application encryption.
  if (endpoint.channel === 'legacy') {
    return requestNode(
      endpoint,
      controlRequest.url,
      controlRequest.method,
      controlRequest.body,
      timeoutMs,
      true,
    );
  }

  const key = deriveControlKey(endpoint.token);
  const requestId = randomUUID();
  const envelope = sealControlMessage(key, 'request', requestId, controlRequest);
  const outer = await requestNode(
    endpoint,
    '/api/secure/rpc',
    'POST',
    JSON.stringify(envelope),
    timeoutMs,
    false,
  );
  if (outer.status !== 200) {
    // The node intentionally does not distinguish bad keys from malformed
    // ciphertext on the wire. Central can still present it as an auth error.
    throw Object.assign(new Error('Encrypted control channel rejected the request'), {
      status: outer.status === 400 ? 401 : outer.status,
    });
  }
  const responseEnvelope = JSON.parse(outer.body) as unknown;
  const opened = openControlMessage<ControlResponse>(key, 'response', responseEnvelope);
  if (opened.requestId !== requestId || !opened.payload || typeof opened.payload !== 'object' ||
    !Number.isInteger(opened.payload.status) || typeof opened.payload.body !== 'string') {
    throw new Error('Invalid encrypted control response');
  }
  return { status: opened.payload.status, body: opened.payload.body };
};

export class NodeClient {
  private readonly timeoutMs: number;
  private readonly maxPageSize: number;

  constructor(timeoutMs = DEFAULT_NODE_TIMEOUT_MS, maxPageSize = DEFAULT_MAX_PAGE_SIZE) {
    this.timeoutMs = timeoutMs;
    this.maxPageSize = maxPageSize;
  }

  /** Fetch node identity from GET /api/node/info. Returns null on non-identity errors (no auth, not found, etc.). */
  async fetchIdentity(endpoint: NodeEndpoint): Promise<NodeIdentityResponse | NodeClientError> {
    try {
      return parseNodeResponse<NodeIdentityResponse>(await requestControl(endpoint, {
        method: 'GET',
        url: '/api/node/info',
      }, this.timeoutMs));
    } catch (e) {
      return toError(e);
    }
  }

  /**
   * Poll events for a node using cursor-based pagination.
   * Returns the page data, or an error. Does not follow redirects.
   */
  async fetchEvents(
    endpoint: NodeEndpoint,
    siteId: string,
    streamId: string,
    cursor: string | null = null
  ): Promise<EventPage | NodeClientError> {
    try {
      const params = new URLSearchParams();
      params.set('after', cursor ?? '');
      params.set('limit', String(this.maxPageSize));
      params.set('site_id', siteId);
      params.set('stream_id', streamId);
      const requestPath = `/api/events?${params.toString()}`;
      return parseNodeResponse<EventPage>(await requestControl(endpoint, {
        method: 'GET',
        url: requestPath,
      }, this.timeoutMs));
    } catch (e) {
      return toError(e);
    }
  }

  /**
   * Send an idempotent command to a node. The node executes it once and
   * records the outcome in its audit journal. Does not follow redirects
   * and enforces the same timeout/size boundaries as other calls.
   */
  async fetchCommand(
    endpoint: NodeEndpoint,
    commandId: string,
    type: string,
    params: Record<string, unknown>
  ): Promise<NodeCommandResponse | NodeClientError> {
    try {
      let commandPath = '/api/commands';
      if (type === 'control.restart') {
        commandPath = '/api/control/restart';
      } else if (type === 'control.rotate_challenges') {
        commandPath = '/api/control/rotate_challenges';
      }
      const body = JSON.stringify({ command_id: commandId, type, params });
      return parseNodeResponse<NodeCommandResponse>(await requestControl(endpoint, {
        method: 'POST',
        url: commandPath,
        body,
      }, this.timeoutMs));
    } catch (e) {
      return toError(e);
    }
  }
}

export const createNodeClient = (timeoutMs = DEFAULT_NODE_TIMEOUT_MS, maxPageSize = DEFAULT_MAX_PAGE_SIZE): NodeClient =>
  new NodeClient(timeoutMs, maxPageSize);
