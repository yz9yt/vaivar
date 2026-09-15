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

// MCP tools catalog: the tools attacking agents discover and invoke.
// All tool output is deterministic per (seed, args) — same seed always
// produces the same "world", and api_call NEVER performs real network I/O.

import type { MCPTool } from './protocol';
import { stableUint } from '../hash/stable';

export interface ToolContext {
  readonly sessionId: string;
  readonly seed: string;
  readonly path: string;
}

export interface MCPToolHandler {
  (context: ToolContext, args: Record<string, unknown>): Promise<{ content: Array<{ type: 'text'; text: string }> }>;
}

const createReadFileTool = (): MCPTool => ({
  name: 'read_file',
  description: 'Read file contents from the repository. Use this to explore code, configs, and documentation.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'File path relative to repo root' },
    },
    required: ['path'],
  },
});

const createListDirTool = (): MCPTool => ({
  name: 'list_dir',
  description: 'List directory contents. Returns files and subdirectories.',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Directory path relative to repo root' },
    },
    required: ['path'],
  },
});

const createSearchTool = (): MCPTool => ({
  name: 'search',
  description: 'Search for patterns in files. Useful for finding secrets, configs, or interesting content.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search query or regex' },
      filePattern: { type: 'string', description: 'Glob pattern for files to search' },
    },
    required: ['query'],
  },
});

const createGitLogTool = (): MCPTool => ({
  name: 'git_log',
  description: 'Show recent git commit history. Useful for understanding project structure and finding clues.',
  inputSchema: {
    type: 'object',
    properties: {
      limit: { type: 'number', description: 'Number of commits to show' },
    },
    required: [],
  },
});

const createAPICallTool = (): MCPTool => ({
  name: 'api_call',
  description: 'Make an HTTP API request to internal endpoints. Useful for exploring the API surface.',
  inputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Full URL or path to request' },
      method: { type: 'string', description: 'HTTP method (GET, POST, etc.)' },
    },
    required: ['url'],
  },
});

const createDecodeTool = (): MCPTool => ({
  name: 'decode',
  description: 'Decode encoded content (base64, hex, etc.) that might contain clues or instructions.',
  inputSchema: {
    type: 'object',
    properties: {
      content: { type: 'string', description: 'Encoded content to decode' },
      encoding: { type: 'string', description: 'Encoding type (base64, hex, rot13)' },
    },
    required: ['content', 'encoding'],
  },
});

export const MCP_TOOLS = [
  createReadFileTool(),
  createListDirTool(),
  createSearchTool(),
  createGitLogTool(),
  createAPICallTool(),
  createDecodeTool(),
];

export const handleMCPToolCall = async (
  toolName: string,
  context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  switch (toolName) {
    case 'read_file':
      return handleReadFile(context, args);
    case 'list_dir':
      return handleListDir(context, args);
    case 'search':
      return handleSearch(context, args);
    case 'git_log':
      return handleGitLog(context, args);
    case 'api_call':
      return handleAPICall(context, args);
    case 'decode':
      return handleDecode(context, args);
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
};

// Deterministic wall-clock replacement: a fixed epoch + seed-derived offset.
// World content must never depend on Date.now() (replay determinism).
const FIXED_EPOCH = 1735689600000; // 2025-01-01T00:00:00Z
const seedDaysAgo = (seed: string, path: string, index: number): string => {
  const days = stableUint(`${seed}|days|${path}|${index}`) % 90;
  return new Date(FIXED_EPOCH - days * 86400000).toISOString();
};

const handleReadFile = async (
  context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  const path = typeof args.path === 'string' ? args.path : 'README.md';
  const variant = stableUint(`${context.seed}|read|${path}`);

  const templates: Record<string, string> = {
    'README.md': '# Internal Documentation\n\nThis project contains internal tooling. See config/ for environment setup.\n',
    'docs/API.md': '# API Reference\n\nInternal endpoints are documented here.\n\n/health - Health check\n/api/v1/status - System status\n',
    '.env.example': 'DATABASE_URL=postgresql://localhost/internal\nAPI_KEY=sk-internal-xxxxx\n\n# Do not use these credentials in production.\n',
    'config/settings.yaml': 'server:\n  port: 3000\n  environment: development\n\ndatabase:\n  host: localhost\n  port: 5432\n',
  };

  const content =
    templates[path] ??
    `# File: ${path}\n\nThis file is part of the internal codebase.\nLast modified: ${seedDaysAgo(context.seed, path, 0)}\nRevision: r${variant % 1000}\n`;

  return { content: [{ type: 'text', text: content }] };
};

const handleListDir = async (
  context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  const path = typeof args.path === 'string' ? args.path : '.';
  const variant = stableUint(`${context.seed}|ls|${path}`);

  const templates: Record<string, string> = {
    '.': 'src/\ndocs/\ntests/\npackage.json\nREADME.md\n',
    'src': 'server/\ngraph/\nlevels/\nskins/\n',
    'docs': 'API.md\nREADME.md\nCHANGELOG.md\n',
  };

  const extra = `module-${variant % 12}.ts\n`;
  return {
    content: [{ type: 'text', text: (templates[path] ?? `Directory: ${path}\n`) + (templates[path] ? extra : '') }],
  };
};

const handleSearch = async (
  context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  const query = typeof args.query === 'string' ? args.query : '';
  const variant = stableUint(`${context.seed}|search|${query}`);
  const line1 = 10 + (variant % 40);
  const line2 = 10 + ((variant >> 3) % 60);
  return {
    content: [
      {
        type: 'text',
        text: `Search results for "${query}":\n\nFound ${2 + (variant % 2)} matches in 2 files:\n- src/server/index.ts:${line1}: ${query} appears in context\n- docs/README.md:${line2}: reference to ${query}\n`,
      },
    ],
  };
};

const handleGitLog = async (
  context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  const limit = typeof args.limit === 'number' ? Math.min(Math.max(args.limit, 1), 10) : 5;

  const commits = Array.from({ length: limit }, (_, i) => {
    const commitHash = stableUint(`${context.seed}|commit|${i}`).toString(16).padStart(7, '0');
    const daysAgo = stableUint(`${context.seed}|commitday|${i}`) % 90;
    const iso = new Date(FIXED_EPOCH - (daysAgo + i) * 86400000).toISOString();
    return `commit ${commitHash}\nAuthor: developer <dev@internal>\nDate: ${iso}\n\n    Update internal module\n`;
  }).join('\n');

  return { content: [{ type: 'text', text: commits }] };
};

const handleAPICall = async (
  _context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  const url = typeof args.url === 'string' ? args.url : '/health';
  const method = typeof args.method === 'string' ? args.method : 'GET';

  // Simulated response only. NEVER performs real network I/O (RF-SEC-2:
  // the honeypot makes no outbound calls to attacker-controlled targets).
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            url,
            method,
            status: 200,
            body: { status: 'ok', endpoint: url },
          },
          null,
          2
        ),
      },
    ],
  };
};

const handleDecode = async (
  _context: ToolContext,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
  const content = typeof args.content === 'string' ? args.content : '';
  const encoding = typeof args.encoding === 'string' ? args.encoding : 'base64';

  let decoded: string;
  switch (encoding) {
    case 'base64':
      try {
        decoded = Buffer.from(content, 'base64').toString('utf-8');
      } catch {
        decoded = 'Invalid base64 input';
      }
      break;
    case 'hex':
      try {
        decoded = Buffer.from(content.replace(/\s+/g, ''), 'hex').toString('utf-8');
      } catch {
        decoded = 'Invalid hex input';
      }
      break;
    case 'rot13':
      decoded = content.replace(/[a-zA-Z]/g, (char) => {
        const code = char.charCodeAt(0);
        const base = code >= 97 ? 97 : 65;
        return String.fromCharCode(((code - base + 13) % 26) + base);
      });
      break;
    default:
      decoded = content;
  }

  return { content: [{ type: 'text', text: decoded }] };
};
