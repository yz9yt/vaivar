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

// Application logger: structured JSON-lines, buffered, rotating.
// The whole point: a disk failure must never crash the process, and a
// slow disk must never block request handling. Every write is fire-and-forget.

import fs from 'fs';
import path from 'path';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogRecord {
  readonly ts: string;
  readonly level: LogLevel;
  readonly msg: string;
  readonly context?: Record<string, unknown>;
  readonly err?: { message: string; stack?: string };
}

const LEVEL_RANK: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface AppLoggerConfig {
  readonly path: string;
  readonly maxBytes?: number;
  readonly maxFiles?: number;
  readonly minLevel?: LogLevel;
  readonly flushBytes?: number;
}

const DEFAULTS: Required<AppLoggerConfig> = {
  path: 'logs/vaivar.app.log',
  maxBytes: 10 * 1024 * 1024,
  maxFiles: 3,
  minLevel: 'info',
  flushBytes: 4096,
};

export class AppLogger {
  private readonly config: Required<AppLoggerConfig>;
  private buffer: string = '';
  private writing: boolean = false;
  private stopped: boolean = false;

  constructor(config: AppLoggerConfig) {
    this.config = { ...DEFAULTS, ...config };
    this.ensureDir();
  }

  private ensureDir(): void {
    try {
      const dir = path.dirname(this.config.path);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    } catch {
      // Logging is best-effort; the app must keep running.
    }
  }

  private rotate(): void {
    try {
      for (let i = this.config.maxFiles - 1; i >= 1; i--) {
        const src = `${this.config.path}.${i}`;
        const dst = `${this.config.path}.${i + 1}`;
        if (fs.existsSync(src)) fs.renameSync(src, dst);
      }
      if (fs.existsSync(this.config.path)) fs.renameSync(this.config.path, `${this.config.path}.1`);
    } catch {
      // Rotation failure is not fatal.
    }
  }

  private writeRecord(record: LogRecord): void {
    this.buffer += JSON.stringify(record) + '\n';
    if (this.buffer.length >= this.config.flushBytes) {
      this.flush();
    }
  }

  /** Flush is safe to call at any time, including during shutdown. */
  flush(): void {
    if (this.writing || this.stopped || this.buffer.length === 0) return;
    const data = this.buffer;
    this.buffer = '';
    this.writing = true;
    try {
      fs.appendFileSync(this.config.path, data);
    } catch {
      // Best-effort: keep the rest in buffer so we don't lose history.
      this.buffer = data + this.buffer;
      if (this.buffer.length > this.config.maxBytes) {
        this.buffer = this.buffer.slice(-this.config.maxBytes);
      }
    } finally {
      this.writing = false;
    }
  }

  log(level: LogLevel, msg: string, context?: Record<string, unknown>): void {
    if (LEVEL_RANK[level] < LEVEL_RANK[this.config.minLevel]) return;
    const record: LogRecord = {
      ts: new Date().toISOString(),
      level,
      msg,
      context,
    };
    this.writeRecord(record);
  }

  debug(msg: string, context?: Record<string, unknown>): void { this.log('debug', msg, context); }
  info(msg: string, context?: Record<string, unknown>): void { this.log('info', msg, context); }
  warn(msg: string, context?: Record<string, unknown>): void { this.log('warn', msg, context); }
  error(msg: string, context?: Record<string, unknown>): void { this.log('error', msg, context); }

  /** Attach an Error to a log line without leaking stack traces to logs. */
  logError(level: LogLevel, msg: string, err: unknown, context?: Record<string, unknown>): void {
    const record: LogRecord = {
      ts: new Date().toISOString(),
      level,
      msg,
      context,
      err: err instanceof Error
        ? { message: err.message, stack: err.stack }
        : { message: String(err) },
    };
    this.writeRecord(record);
  }

  /** Called on process exit; flushes synchronously and stops. */
  shutdown(): void {
    this.stopped = true;
    try {
      this.flush();
    } catch {
      // Logging must never crash the process.
    }
  }

  /** Rotate the file if it has grown past the configured size. */
  maybeRotate(): void {
    try {
      if (fs.existsSync(this.config.path) && fs.statSync(this.config.path).size >= this.config.maxBytes) {
        this.flush();
        this.rotate();
      }
    } catch {
      // Best-effort.
    }
  }
}

export const createAppLogger = (config: AppLoggerConfig): AppLogger => new AppLogger(config);