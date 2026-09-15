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

// vAIvar OpenAPI Skin
// Presents the system as an OpenAPI-based REST service

import { derive } from '../engine/derivation';

/**
 * Deterministic OpenAPI skin. Document content is derived from the seed so
 * two sessions see different API surfaces (anti-KB), without ever exposing
 * the seed itself.
 */
export interface OpenAPISkinConfig {
  readonly title: string;
  readonly version: string;
  readonly basePath: string;
  readonly seed: string;
}

export interface OpenAPIPathItem {
  readonly summary: string;
  readonly description: string;
  readonly responses: Record<string, {
    readonly description: string;
    readonly content?: Record<string, unknown>;
  }>;
}

export interface OpenAPIDocument {
  readonly openapi: string;
  readonly info: {
    readonly title: string;
    readonly version: string;
    readonly description: string;
  };
  readonly servers: Array<{ readonly url: string }>;
  readonly paths: Record<string, OpenAPIPathItem>;
}

/**
 * Derive a deterministic variant from the seed WITHOUT slicing raw seed bytes.
 * Uses domain-separated HMAC so no part of the seed is ever exposed in output.
 */
const deriveVariant = (seed: string, index: number): number => {
  const derived = derive(seed, 'openapi-variant', String(index), 4);
  return parseInt(derived.slice(0, 8), 16) % 1000;
};

export const createOpenAPISkin = (config: OpenAPISkinConfig): OpenAPIDocument => {
  const { title, version, basePath, seed } = config;

  // Seed-derived surface: the number and shape of endpoints vary per session.
  const endpoints = [
    '/api/v1/status',
    '/api/v1/health',
    '/api/v1/config',
    `/api/v1/projects/${deriveVariant(seed, 1)}`,
    `/api/v1/records/${deriveVariant(seed, 2)}`,
  ].slice(0, 3 + (deriveVariant(seed, 0) % 3));

  const paths: Record<string, OpenAPIPathItem> = {};
  for (const endpoint of endpoints) {
    paths[endpoint] = {
      summary: endpoint.endsWith('/health') ? 'Health check endpoint' : 'Service operation',
      description: 'Kubernetes-compatible health check endpoint'.slice(0, endpoint.endsWith('/health') ? 48 : 16),
      responses: {
        '200': {
          description: 'Operation completed',
          content: {
            'application/json': {
              schema: { type: 'object' },
            },
          },
        },
      },
    };
  }

  return {
    openapi: '3.0.3',
    info: {
      title: title || 'Internal API Service',
      version: version || '1.0.0',
      description: 'Internal REST API for service operations',
    },
    servers: [{ url: basePath }],
    paths,
  };
};
