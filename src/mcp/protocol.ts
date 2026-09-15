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

// vAIvar MCP Protocol - Model Context Protocol adapter
// Allows attacking agents to discover and invoke tools

export interface MCPRequest {
  readonly jsonrpc: '2.0';
  readonly id: string | number | null;
  readonly method: string;
  readonly params?: unknown;
}

export interface MCPResponse {
  readonly jsonrpc: '2.0';
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export interface MCPTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Record<string, unknown>;
    readonly required?: string[];
  };
}

export interface MCPResource {
  readonly uri: string;
  readonly name: string;
  readonly description?: string;
  readonly mimeType?: string;
}

export type MCPNotification =
  | { readonly method: 'notifications/progress'; readonly params: { readonly progress: number; readonly total: number; readonly message?: string } }
  | { readonly method: 'notifications/log'; readonly params: { readonly level: 'info' | 'warn' | 'error'; readonly message: string } };

export const MCP_METHOD_INITIALIZE = 'initialize';
export const MCP_METHOD_TOOLS_LIST = 'tools/list';
export const MCP_METHOD_TOOLS_CALL = 'tools/call';
export const MCP_METHOD_RESOURCES_LIST = 'resources/list';
export const MCP_METHOD_RESOURCES_READ = 'resources/read';

export const createMCPRequest = (
  id: string | number,
  method: string,
  params?: unknown
): MCPRequest => ({
  jsonrpc: '2.0',
  id,
  method,
  params,
});

export const createMCPResponse = (
  id: string | number,
  result: unknown
): MCPResponse => ({
  jsonrpc: '2.0',
  id,
  result,
});

export const createMCPError = (
  id: string | number,
  code: number,
  message: string,
  data?: unknown
): MCPResponse => ({
  jsonrpc: '2.0',
  id,
  error: { code, message, data },
});

export const parseMCPMessage = (message: string): MCPRequest | MCPResponse => {
  try {
    const parsed = JSON.parse(message);
    if (parsed.jsonrpc === '2.0') {
      return parsed as MCPRequest | MCPResponse;
    }
    throw new Error('Invalid MCP message: missing jsonrpc version');
  } catch (e) {
    throw new Error(`MCP parse error: ${e instanceof Error ? e.message : 'unknown error'}`);
  }
};