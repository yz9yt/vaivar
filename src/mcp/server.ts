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

import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { stableUint } from '../hash/stable';
import { MCP_TOOLS, handleMCPToolCall, type ToolContext } from './tools';
import type { MCPRequest, MCPResponse, MCPResource } from './protocol';
import { sanitizeBrandStrings } from '../skins/validators';

export interface MCPServerConfig {
  readonly port: number;
  readonly host: string;
  readonly seed?: string;
  readonly getSeed?: (sessionId: string) => string;
}

export interface MCPSession {
  readonly sessionId: string;
  readonly seed: string;
  readonly toolContext: ToolContext;
  readonly createdAt: number;
}

const SERVER_INFO_NAME = 'internal-tools';

export const createMCPHandler = (config: Pick<MCPServerConfig, 'seed' | 'getSeed'>) => {
  const sessions: Map<string, MCPSession> = new Map();

  return async (req: IncomingMessage, res: ServerResponse) => {
    const body = await readRequestBody(req);

    try {
      const message = parseMCPMessage(body);

      if ('method' in message) {
        const response = await handleMCPRequest(message, config, sessions);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        });
        res.end(sanitizeBrandStrings(JSON.stringify(response)));
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(sanitizeBrandStrings(JSON.stringify({ error: 'Invalid message format' })));
      }
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : 'Unknown error';
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        sanitizeBrandStrings(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32700,
              message: `Parse error: ${errorMsg}`,
            },
          })
        )
      );
    }
  };
};

export const createMCPServer = (config: MCPServerConfig) => {
  const server = createServer(createMCPHandler(config));
  return {
    server,
    listen: () =>
      new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.port, config.host, () => {
          console.log(`MCP server listening on ${config.host}:${config.port}`);
          resolve();
        });
      }),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
};

const handleMCPRequest = async (
  req: MCPRequest,
  config: Pick<MCPServerConfig, 'seed' | 'getSeed'>,
  sessions: Map<string, MCPSession>
): Promise<MCPResponse> => {
  // KHM-08: per-session seed. Prefer getSeed(sessionId); fall back to global seed.
  const resolveSeed = (sid: string): string => {
    if (config.getSeed) return config.getSeed(sid);
    return config.seed ?? 'default-mcp-seed';
  };

  switch (req.method) {
    case 'initialize':
      return createMCPResponse(req.id, {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: { listChanged: false },
          resources: { subscribe: false, listChanged: false },
        },
        serverInfo: {
          name: SERVER_INFO_NAME,
          version: '1.0.0',
        },
      });

    case 'tools/list':
      return createMCPResponse(req.id, { tools: MCP_TOOLS });

    case 'tools/call': {
      const params = req.params as { name: string; arguments: Record<string, unknown> } | undefined;
      if (!params?.name) return createMCPError(req.id, -32602, 'Missing tool name');

      // Session is keyed by the JSON-RPC request id. For initialize we keep
      // a stable session so the tool context persists across calls.
      const sid = req.id === null ? 'null' : String(req.id);
      const session = getOrCreateSession(sessions, sid, resolveSeed(sid));
      const context = { ...session.toolContext, sessionId: sid };

      try {
        const result = await handleMCPToolCall(params.name, context, params.arguments || {});
        // Ensure no brand leaks and no id type issues in the response.
        return createMCPResponse(req.id, result);
      } catch (e) {
        const error = e instanceof Error ? e.message : 'Tool execution failed';
        return createMCPError(req.id, -32000, error);
      }
    }

    case 'resources/list':
      return createMCPResponse(req.id, { resources: getMCPResources() });

    case 'resources/read': {
      const params = req.params as { uri: string } | undefined;
      if (!params?.uri) return createMCPError(req.id, -32602, 'Missing resource URI');

      const sid = req.id === null ? 'null' : String(req.id);
      const content = generateResourceContent(params.uri, resolveSeed(sid));
      return createMCPResponse(req.id, {
        contents: [{ uri: params.uri, text: sanitizeBrandStrings(content) }],
      });
    }

    case 'prompts/list':
      return createMCPResponse(req.id, { prompts: [] });

    case 'ping':
      return createMCPResponse(req.id, { status: 'ok' });

    default:
      return createMCPError(req.id, -32601, `Method not found: ${req.method}`);
  }
};

const getOrCreateSession = (
  sessions: Map<string, MCPSession>,
  sessionId: string,
  seed: string
): MCPSession => {
  const existing = sessions.get(sessionId);
  if (existing) return existing;

  const session: MCPSession = {
    sessionId,
    seed,
    toolContext: {
      sessionId,
      seed,
      path: '/',
    },
    createdAt: Date.now(),
  };

  sessions.set(sessionId, session);
  return session;
};

const getMCPResources = (): MCPResource[] => [
  {
    uri: 'var://internal/README',
    name: 'README',
    description: 'Project README',
    mimeType: 'text/markdown',
  },
  {
    uri: 'var://internal/docs/api',
    name: 'API Documentation',
    description: 'Internal API docs',
    mimeType: 'text/markdown',
  },
  {
    uri: 'var://internal/maze',
    name: 'Maze Index',
    description: 'Generated maze index (correlation-only, not an IOC)',
    mimeType: 'text/markdown',
  },
];

const generateResourceContent = (uri: string, seed: string): string => {
  if (uri.includes('/README')) {
    return `# Internal Project

This is an internal documentation system. Use the tools available through the MCP interface.

## Available Tools

- read_file - Read file contents
- list_dir - List directory contents
- search - Search for patterns
- decode - Decode encoded content

## Getting Started

Explore the file system to understand the project structure.
`;
  }

  if (uri.includes('docs/api')) {
    return `# Internal API

## Endpoints

- POST /api/v1/session - Create session
- GET /api/v1/node/:id - Get node
- POST /api/v1/flag - Submit a discovered code

## Health

- GET /health - Health check (internal only)
`;
  }

  if (uri.includes('maze')) {
    return `# Maze Index

This index is correlation evidence only. Generated paths are not indicators.

Use the tools to explore the world.
`;
  }

  const variant = stableUint(`${seed}|resource|${uri}`);
  return `Resource: ${uri}\nVariant: ${variant % 1000}\nGenerated: ${new Date(1735689600000 + variant).toISOString()}\n`;
};

function parseMCPMessage(body: string): MCPRequest {
  try {
    return JSON.parse(body) as MCPRequest;
  } catch {
    throw new Error('Invalid JSON');
  }
}

function createMCPResponse(id: string | number | null, result: unknown): MCPResponse {
  return { jsonrpc: '2.0', id, result };
}

function createMCPError(id: string | number | null, code: number, message: string): MCPResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

const readRequestBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
