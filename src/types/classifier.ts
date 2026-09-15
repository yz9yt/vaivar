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

export type AgentClass = 'known' | 'scanner' | 'human_llm' | 'autonomous' | 'unknown';

export interface Classification {
  readonly confidence: number;
  readonly class: AgentClass;
  readonly tools: string[];
}

export interface Request {
  readonly path: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly userAgent: string;
  readonly body?: string;
}

export interface ClassifierConfig {
  readonly mediumAgentRequests: number;
  readonly highAgentRequests: number;
  readonly mediumDwellSeconds: number;
  readonly highDwellSeconds: number;
  readonly burstThresholdMs: number;
  readonly thinkTimeThresholdMs: number;
}

export const DEFAULT_CLASSIFIER_CONFIG: ClassifierConfig = {
  mediumAgentRequests: 80,
  highAgentRequests: 800,
  mediumDwellSeconds: 7200,
  highDwellSeconds: 86400,
  burstThresholdMs: 100,
  thinkTimeThresholdMs: 1000,
};