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

// OpenCTI EXTERNAL_IMPORT connector.
//
// Emits vaivar.event.v1 -> STIX 2.1 -> POST to OpenCTI. When no OpenCTI URL
// is configured, bundles are queued in memory (bounded) so the engine still
// works in standalone mode.

import type { Event } from '../types/events';
import { eventToStixBundle, type STIXBundle } from './transform';

export interface OpenCTIConfig {
  readonly url: string;
  readonly token: string;
  readonly updateType?: 'CREATE_UPDATE' | 'UPDATE' | 'CREATE';
  readonly confidence?: number;
  readonly organizationId?: string;
  /** Max retry attempts for a failing bundle. */
  readonly maxRetries?: number;
  /** Max queued bundles when OpenCTI is unreachable. */
  readonly maxQueue?: number;
}

export interface OpenCTIResponse {
  readonly success: boolean;
  readonly status?: number;
  readonly error?: string;
}

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MAX_QUEUE = 1000;

export class OpenCTIConnector {
  private readonly config: Required<OpenCTIConfig>;
  private queue: STIXBundle[] = [];
  private eventCount = 0;
  private sentCount = 0;
  private failedCount = 0;

  constructor(config: OpenCTIConfig) {
    this.config = {
      url: config.url,
      token: config.token,
      updateType: config.updateType ?? 'CREATE_UPDATE',
      confidence: config.confidence ?? 75,
      organizationId: config.organizationId ?? '',
      maxRetries: config.maxRetries ?? DEFAULT_MAX_RETRIES,
      maxQueue: config.maxQueue ?? DEFAULT_MAX_QUEUE,
    };
  }

  get enabled(): boolean {
    return Boolean(this.config.url && this.config.token);
  }

  /** Handle a vaivar.event.v1 event: translate to STIX and ship/queue. */
  async handleEvent(event: Event): Promise<void> {
    this.eventCount += 1;
    const bundle = eventToStixBundle(event);
    if (!this.enabled) {
      this.enqueue(bundle);
      return;
    }
    await this.sendWithRetry(bundle);
  }

  private enqueue(bundle: STIXBundle): void {
    if (this.queue.length >= this.config.maxQueue) {
      this.queue.shift(); // drop oldest to bound memory
    }
    this.queue.push(bundle);
  }

  async sendWithRetry(bundle: STIXBundle): Promise<OpenCTIResponse> {
    let lastError = '';
    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      const result = await this.sendBundle(bundle);
      if (result.success) {
        this.sentCount += 1;
        return result;
      }
      lastError = result.error ?? 'unknown';
      if (attempt < this.config.maxRetries) {
        await delay(Math.pow(2, attempt) * 1000);
      }
    }
    this.failedCount += 1;
    this.enqueue(bundle);
    return { success: false, error: lastError };
  }

  /** Real HTTP POST to OpenCTI. */
  async sendBundle(bundle: STIXBundle): Promise<OpenCTIResponse> {
    try {
      const response = await fetch(`${this.config.url.replace(/\/$/, '')}/api/v1/stix2`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.config.token}`,
          'x-opencti-token': this.config.token,
        },
        body: JSON.stringify(bundle),
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        return { success: false, status: response.status, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
      }
      return { success: true, status: response.status };
    } catch (e) {
      return { success: false, error: e instanceof Error ? e.message : 'network error' };
    }
  }

  /** Flush the in-memory queue (e.g. after a reconnect). */
  async flush(): Promise<OpenCTIResponse[]> {
    const results: OpenCTIResponse[] = [];
    while (this.queue.length > 0) {
      const bundle = this.queue.shift()!;
      results.push(await this.sendWithRetry(bundle));
    }
    return results;
  }

  getStatistics(): {
    eventCount: number;
    sentCount: number;
    failedCount: number;
    queued: number;
    enabled: boolean;
  } {
    return {
      eventCount: this.eventCount,
      sentCount: this.sentCount,
      failedCount: this.failedCount,
      queued: this.queue.length,
      enabled: this.enabled,
    };
  }

  clear(): void {
    this.queue = [];
    this.eventCount = 0;
    this.sentCount = 0;
    this.failedCount = 0;
  }
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export const createOpenCTIConnector = (config: OpenCTIConfig): OpenCTIConnector =>
  new OpenCTIConnector(config);
