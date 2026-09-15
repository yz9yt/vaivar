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

type EventSink = {
  readonly name: string;
  accepts: (e: unknown) => boolean;
  write: (e: unknown) => Promise<void>;
};

/** Shape of an event forwarded from an Edge node. The Edge stamps it with its
 * `site_id` so the central plane can correlate across deployments. */
export interface ForwardedEvent {
  readonly site_id: string;
  readonly payload: unknown;
}

export interface RemoteSinkConfig {
  /** Central collector base URL, supplied by the deployment environment. */
  readonly url: string;
  /** Bearer token the central plane expects (VAIVAR_CENTRAL_TOKEN). */
  readonly token: string;
  /** Site identifier stamped on every forwarded event. */
  readonly siteId: string;
  /** Max retry attempts with exponential backoff. */
  readonly maxRetries?: number;
  /** Bounded in-memory queue so a downstream outage cannot stall the engine. */
  readonly maxQueue?: number;
}

import { randomUUID } from 'node:crypto';
import {
  deriveControlKey,
  openControlMessage,
  sealControlMessage,
  type ControlResponse,
} from '../security/control-channel';

/**
 * Event sink that forwards engine events to the central control plane inside
 * an application-encrypted envelope. The socket may be plain HTTP: neither
 * the ingest token nor event content is put in HTTP headers or cleartext.
 * Mirrors the OpenCTI connector contract: queue on failure, flush on
 * reconnect, never block the engine.
 */
export class RemoteEventSink {
  private readonly url: string;
  private readonly token: string;
  private readonly siteId: string;
  private readonly maxRetries: number;
  private readonly maxQueue: number;
  private queue: ForwardedEvent[] = [];
  private drainPromise: Promise<void> | null = null;
  private sentCount = 0;
  private failedCount = 0;
  private droppedCount = 0;

  constructor(config: RemoteSinkConfig) {
    this.url = config.url.replace(/\/$/, '');
    this.token = config.token;
    this.siteId = config.siteId;
    this.maxRetries = config.maxRetries ?? 3;
    this.maxQueue = config.maxQueue ?? 1000;
  }

  get enabled(): boolean {
    return Boolean(this.url && this.token && this.siteId);
  }

  /** Adapt to the EventBus sink interface. */
  asSink(): EventSink {
    return {
      name: 'remote',
      accepts: () => this.enabled,
      write: async (e: unknown) => {
        if (!this.enabled) return;
        await this.enqueueAndFlush({ site_id: this.siteId, payload: e });
      },
    };
  }

  private enqueueAndFlush(event: ForwardedEvent): Promise<void> {
    this.queue.push(event);
    // Event delivery is deliberately fire-and-forget for the engine. Central
    // shutdown/tests can call flush() when they need to await the work.
    void this.startDrain();
    return Promise.resolve();
  }

  private startDrain(): Promise<void> {
    if (this.drainPromise) return this.drainPromise;
    this.drainPromise = this.drain().finally(() => {
      this.drainPromise = null;
    });
    return this.drainPromise;
  }

  private async drain(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0, 64);
      const sent = await this.sendBatch(batch);
      if (!sent) return;
    }
  }

  private async sendBatch(batch: ForwardedEvent[]): Promise<boolean> {
    let lastError = '';
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const result = await this.postBatch(batch);
      if (result.success) {
        this.sentCount += batch.length;
        return true;
      }
      lastError = result.error ?? 'unknown';
      if (attempt < this.maxRetries) await delay(backoff(attempt));
    }
    this.failedCount += 1;
    // Drop oldest to keep the queue bounded; the central plane reconciles by
    // deterministic event ids, so transient loss is not fatal.
    while (this.queue.length + batch.length > this.maxQueue) {
      const overflow = this.queue.length + batch.length - this.maxQueue;
      if (overflow <= 0) break;
      const drop = this.queue.splice(0, overflow);
      this.droppedCount += drop.length;
    }
    this.enqueue(batch);
    void Promise.resolve().then(() => void lastError);
    return false;
  }

  private enqueue(batch: ForwardedEvent[]): void {
    this.queue.push(...batch);
  }

  private async postBatch(batch: ForwardedEvent[]): Promise<{ success: boolean; error?: string; status?: number }> {
    try {
      const requestId = randomUUID();
      const envelope = sealControlMessage(
        deriveControlKey(this.token),
        'request',
        requestId,
        batch,
      );
      const response = await fetch(`${this.url}/api/v1/events/secure`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(envelope),
      });
      const responseBody = await response.text().catch(() => '');
      if (!response.ok) {
        return { success: false, status: response.status, error: `HTTP ${response.status}: ${responseBody.slice(0, 200)}` };
      }
      const opened = openControlMessage<ControlResponse>(
        deriveControlKey(this.token),
        'response',
        JSON.parse(responseBody) as unknown,
      );
      const logical = opened.payload;
      if (opened.requestId !== requestId || !logical || typeof logical !== 'object' ||
        !Number.isInteger(logical.status) || typeof logical.body !== 'string' ||
        logical.status < 200 || logical.status >= 300) {
        return { success: false, status: typeof logical?.status === 'number' ? logical.status : undefined, error: 'Invalid encrypted ingest response' };
      }
      return { success: true, status: response.status };
    } catch (e) {
      return { success: false, error: e instanceof Error ? e.message : 'network error' };
    }
  }

  async flush(): Promise<void> {
    await this.startDrain();
  }

  getStatistics(): {
    queued: number;
    sent: number;
    failed: number;
    dropped: number;
    enabled: boolean;
  } {
    return {
      queued: this.queue.length,
      sent: this.sentCount,
      failed: this.failedCount,
      dropped: this.droppedCount,
      enabled: this.enabled,
    };
  }
}

export const createRemoteEventSink = (config: RemoteSinkConfig): RemoteEventSink =>
  new RemoteEventSink(config);

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const backoff = (attempt: number): number => Math.min(30000, 1000 * 2 ** attempt);
