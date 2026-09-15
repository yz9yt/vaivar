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

export { createMCPServer, type MCPServerConfig, type MCPSession } from './server';
export { createMCPRequest, createMCPResponse, createMCPError, type MCPRequest, type MCPResponse } from './protocol';
export { MCP_TOOLS, handleMCPToolCall, type MCPToolHandler, type ToolContext } from './tools';
export type { MCPTool, MCPResource } from './protocol';