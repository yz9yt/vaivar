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

// Splunk HTTP Event Collector (HEC) export adapter.
//
// Runs exclusively in the central plane. It receives projected
// `HecEvent`s, batches them, and POSTs to Splunk's
// `/services/collector` endpoint (newline-delimited JSON). Each
// destination keeps its own HEC token, delivery cursor and retry
// state, so a Splunk outage never blocks node polling.
//
// Reference:
//  - https://help.splunk.com/en/data-management/collect-http-event-data/use-hec-in-splunk-enterprise/http-event-collector-rest-api-endpoints

import type { HecEvent } from './splunk-events';

export interface SplunkHecConfig {
  /** Splunk HEC base URL, e.g. https://splunk.example.com:8088. */
  readonly url: string;
  /** HEC token issued by Splunk. */
  readonly token: string;
  /** Optional index override sent on every event. */
  readonly index?: string;
  /** Optional source override sent on every event. */
  readonly source?: string;
  /** Optional sourcetype override. Defaults to 'vaivar:event'. */
  readonly sourcetype?: string;
  /** Max retry attempts on a failing batch. Defaults to 3. */
  readonly maxRetries?: number;
  /** Max queued events before dropping oldest. Defaults to 1000. */
  readonly maxQueue?: number;
  /** Batch size per POST. Defaults to 64. */
  readonly batchSize?: number;
  /** Request timeout in ms. Defaults to 15000. */
  readonly timeoutMs?: number;
}

export interface HecDeliveryRecord {
  readonly destination: string;
  readonly last_sequence: string | null;
  readonly sent_count: number;
  readonly failed_count: number;
  readonly queued_count: number;
  readonly enabled: boolean;
}

export interface HecSendResult {
  readonly success: boolean;
  readonly status?: number;
  readonly error?: string;
}

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MAX_QUEUE = 1000;
const DEFAULT_BATCH_SIZE = 64;
const DEFAULT_TIMEOUT_MS = 15_000;

export class SplunkHecAdapter {
  private readonly url: string;
  private readonly token: string;
  private readonly index: string | undefined;
  private readonly source: string | undefined;
  private readonly sourcetype: string | undefined;
  private readonly maxRetries: number;
  private readonly maxQueue: number;
  private readonly batchSize: number;
  private readonly timeoutMs: number;
  private queue: HecEvent[] = [];
  private draining = false;
  private sentCount = 0;
  private failedCount = 0;

  constructor(config: SplunkHecConfig) {
    this.url = config.url.replace(/\/$/, '');
    this.token = config.token;
    this.index = config.index;
    this.source = config.source;
    this.sourcetype = config.sourcetype;
    this.maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.maxQueue = config.maxQueue ?? DEFAULT_MAX_QUEUE;
    this.batchSize = config.batchSize ?? DEFAULT_BATCH_SIZE;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** True when a HEC URL and token are present. */
  get enabled(): boolean {
    return Boolean(this.url && this.token);
  }

  /**
   * Accept an HEC event. Bounded in-memory queue so a downstream
   * Splunk outage cannot stall the central plane.
   */
  async accept(event: HecEvent): Promise<void> {
    if (!this.enabled) return;
    const routedEvent: HecEvent = {
      ...event,
      ...(this.index !== undefined ? { index: this.index } : {}),
      ...(this.source !== undefined ? { source: this.source } : {}),
      ...(this.sourcetype !== undefined ? { sourcetype: this.sourcetype } : {}),
    };
    this.queue.push(routedEvent);
    while (this.queue.length > this.maxQueue) {
      this.queue.shift();
      this.failedCount += 1;
    }
    if (!this.draining) void this.drain();
  }

  /** Flush all queued events. Returns after the last batch succeeds or is dropped. */
  async flush(): Promise<void> {
    await this.drain();
  }

  /** Current delivery statistics for this destination. */
  getStatistics(): HecDeliveryRecord {
    return {
      destination: this.url,
      last_sequence: null,
      sent_count: this.sentCount,
      failed_count: this.failedCount,
      queued_count: this.queue.length,
      enabled: this.enabled,
    };
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length > 0) {
        const batch = this.queue.splice(0, this.batchSize);
        await this.sendBatch(batch);
      }
    } finally {
      this.draining = false;
      if (this.queue.length > 0) void this.drain();
    }
  }

  private async sendBatch(batch: HecEvent[]): Promise<void> {
    const body = batch.map((e) => JSON.stringify(e)).join('\n');
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const result = await this.post(body);
      if (result.success) {
        this.sentCount += batch.length;
        return;
      }
      if (attempt < this.maxRetries) {
        await delay(backoff(attempt));
      }
    }
    this.failedCount += 1;
    // Drop oldest to keep the queue bounded. The central store and
    // per-destination cursor keep delivery state for reconciliation.
    while (this.queue.length + batch.length > this.maxQueue) {
      this.queue.shift();
    }
  }

  private async post(body: string): Promise<HecSendResult> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await fetch(this.url + '/services/collector', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Splunk ${this.token}`,
          },
          body,
          signal: controller.signal,
        });
        if (!response.ok) {
          const text = await response.text().catch(() => '');
          return { success: false, status: response.status, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
        }
        return { success: true, status: response.status };
      } finally {
        clearTimeout(timer);
      }
    } catch (e) {
      return { success: false, error: e instanceof Error ? e.message : 'network error' };
    }
  }
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const backoff = (attempt: number): number => Math.min(30000, 1000 * 2 ** attempt);

export const createSplunkHecAdapter = (config: SplunkHecConfig): SplunkHecAdapter =>
  new SplunkHecAdapter(config);
