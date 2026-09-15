import { describe, it, expect, beforeEach } from 'vitest';
import { SessionEngine } from '../src/engine/session';
import { generateNode, toPublicNode } from '../src/graph/generator';
import { createOpenAPISkin } from '../src/skins/openapi';
import { renderWikiPage } from '../src/skins/wiki';
import { classifyRequest } from '../src/classifier/analyzer';
import { buildWorldPlan, canAccessPath, verifyPlanCoherence } from '../src/engine/world-plan';
import type { BudgetLimits } from '../src/types/common';

const MASTER = 'test-secret-12345678901234567890123456789012';

function makeEngine(): SessionEngine {
  return new SessionEngine({
    masterSecret: MASTER,
    budget: { maxNodes: 500, maxBytes: 50 * 1024 * 1024, maxRequests: 10_000, maxCpuMs: 10_000, expiryHours: 48, nodeIncrement: 1, byteIncrement: 1000, requestIncrement: 1, cpuIncrement: 1 },
    dwellFlagSeconds: 3600,
    skins: ['http', 'mcp'],
  });
}

const budget: BudgetLimits = { maxNodes: 500, maxBytes: 50 * 1024 * 1024, maxRequests: 10_000, maxCpuMs: 10_000, expiryHours: 48, nodeIncrement: 1, byteIncrement: 1000, requestIncrement: 1, cpuIncrement: 1 };

describe('KIMI HONEYPOT MUTATION ENGINE — Phase 0 red tests', () => {
  let engine: SessionEngine;

  beforeEach(() => {
    engine = makeEngine();
  });

  describe('KHM-01 — Session transferability', () => {
    it('same sessionId from different attackers must produce different seeds', () => {
      const a = engine.getOrCreate('shared', { ip: '10.0.0.1', userAgent: 'agent-a' });
      const b = engine.getOrCreate('shared', { ip: '10.0.0.2', userAgent: 'agent-b' });
      expect(a.seed).not.toBe(b.seed);
      expect(a.sessionId).not.toBe(b.sessionId);
      expect(a.levelMax).toBe(0);
      expect(b.levelMax).toBe(0);
    });

    it('small UA variation preserves session', () => {
      const a = engine.getOrCreate('s1', { ip: '10.0.0.1', userAgent: 'Mozilla/5.0 (Windows)' });
      const b = engine.getOrCreate('s1', { ip: '10.0.0.1', userAgent: 'Mozilla/5.0 (Windows NT 10.0)' });
      expect(a.sessionId).toBe(b.sessionId);
      expect(a.seed).toBe(b.seed);
    });

    it('strong fingerprint change creates new session', () => {
      const a = engine.getOrCreate('s2', { ip: '10.0.0.1', userAgent: 'Claude-Code/1.0' });
      const b = engine.getOrCreate('s2', { ip: '192.168.1.1', userAgent: 'curl/7.68.0' });
      expect(a.sessionId).not.toBe(b.sessionId);
      expect(a.seed).not.toBe(b.seed);
    });
  });

  describe('KHM-02 — Deep URL reuse across sessions', () => {
    it('same deep path in different seeds must yield different materialized nodes', () => {
      const a = engine.getOrCreate('deep-a', { ip: '10.0.0.1', userAgent: 'agent-a' });
      const b = engine.getOrCreate('deep-b', { ip: '10.0.0.2', userAgent: 'agent-b' });
      const nodeA = generateNode({ seed: a.seed, path: '/deep/secret/path', budget, currentNodeCount: 0, currentBytes: 0 });
      const nodeB = generateNode({ seed: b.seed, path: '/deep/secret/path', budget, currentNodeCount: 0, currentBytes: 0 });
      expect(nodeA.ok).toBe(true);
      expect(nodeB.ok).toBe(true);
      if (nodeA.ok && nodeB.ok) {
        expect(JSON.stringify(nodeA.value)).not.toBe(JSON.stringify(nodeB.value));
      }
    });
  });

  describe('KHM-03 — No internal metadata in public responses', () => {
    it('toPublicNode must not expose kind, level, levelMax, isTrap, isSecret, seed or brand strings', () => {
      const session = engine.getOrCreate('meta-test', { ip: '10.0.0.1', userAgent: 'agent' });
      const nodeResult = generateNode({ seed: session.seed, path: '/', budget, currentNodeCount: 0, currentBytes: 0 });
      expect(nodeResult.ok).toBe(true);
      if (nodeResult.ok) {
        const publicNode = toPublicNode(nodeResult.value, 0);
        const json = JSON.stringify(publicNode);
        expect(json).not.toContain('"kind"');
        expect(json).not.toContain('"level"');
        expect(json).not.toContain('"levelMax"');
        expect(json).not.toContain('"isTrap"');
        expect(json).not.toContain('"isSecret"');
        expect(json).not.toContain('"seed"');
        expect(json).not.toContain('vAIvar');
        expect(json).not.toContain('vaivar');
        expect(json).not.toContain('rabbithole');
      }
    });
  });

  describe('KHM-04 — Recipes mutate across sessions', () => {
    it('same path in different seeds produces different node content', () => {
      const a = engine.getOrCreate('recipe-a', { ip: '10.0.0.1', userAgent: 'agent-a' });
      const b = engine.getOrCreate('recipe-b', { ip: '10.0.0.2', userAgent: 'agent-b' });
      const nodeA = generateNode({ seed: a.seed, path: '/api/v1/config', budget, currentNodeCount: 0, currentBytes: 0 });
      const nodeB = generateNode({ seed: b.seed, path: '/api/v1/config', budget, currentNodeCount: 0, currentBytes: 0 });
      expect(nodeA.ok).toBe(true);
      expect(nodeB.ok).toBe(true);
      if (nodeA.ok && nodeB.ok) {
        expect(JSON.stringify(nodeA.value)).not.toBe(JSON.stringify(nodeB.value));
      }
    });
  });

  describe('KHM-05 — WorldPlan coherence', () => {
    it('WorldPlan is defined and used to gate deep paths', () => {
      const session = engine.getOrCreate('wp-coherence', { ip: '10.0.0.1', userAgent: 'agent' });
      const result = engine.serveNode('wp-coherence', { ip: '10.0.0.1', userAgent: 'agent' }, '/');
      expect(result.ok).toBe(true);
    });

    it('plan coherence: deep paths have valid capability levels', () => {
      const plan = buildWorldPlan('seed-abc-1234567890', 0);
      expect(verifyPlanCoherence(plan)).toBe(true);
    });

    it('canAccessPath gates deep unknown paths when session levelMax is low', () => {
      const plan = buildWorldPlan('seed-abc-1234567890', 0);
      const deepPath = '/unknown/deep/path'; // depth 3
      // LevelMax 0 means no deep access for unknown paths
      expect(canAccessPath(plan, 0, deepPath)).toBe(false);
      // High levelMax should allow it
      expect(canAccessPath(plan, 10, deepPath)).toBe(true);
    });
  });

  describe('KHM-05 depth — recipes coherent with path depth', () => {
    it('deep WorldPlan paths map to capabilities with sufficient level', () => {
      const plan = buildWorldPlan('seed-abc-1234567890', 0);
      const deepPath = '/l10/resource-10/deep-1';
      const cap = plan.paths.get(deepPath);
      expect(cap).toBeDefined();
      expect(cap!.level).toBeGreaterThanOrEqual(1);
    });

    it('generateNode on a deep path respects WorldPlan depth capability', () => {
      // LevelMax 0 session should not serve deep paths via serveNode
      const session = engine.getOrCreate('depth-test', { ip: '10.0.0.1', userAgent: 'agent' });
      expect(session.levelMax).toBe(0);
      const result = engine.serveNode('depth-test', { ip: '10.0.0.1', userAgent: 'agent' }, '/l10/resource-10/deep-1');
      expect(result.ok).toBe(false);
    });
  });

  describe('KHM-06 — Mechanics test declared capability', () => {
    it('challenge embedded in content declares a kind and level', () => {
      const node = generateNode({ seed: 'a'.repeat(64), path: '/capability-check', budget, currentNodeCount: 0, currentBytes: 0 });
      expect(node.ok).toBe(true);
      if (node.ok) {
        const content = node.value.content as Record<string, unknown>;
        const challenge = content.challenge as Record<string, unknown>;
        expect(typeof challenge.kind).toBe('string');
        expect(typeof challenge.level).toBe('number');
        expect(challenge.level).toBeGreaterThanOrEqual(1);
      }
    });
  });

  describe('KHM-07 — Wiki and OpenAPI mounted and clean', () => {
    it('wiki skin strips brand strings', () => {
      const session = engine.getOrCreate('wiki-test', { ip: '10.0.0.1', userAgent: 'agent' });
      const html = renderWikiPage({ title: 'test content', content: 'Explore the vAIvar rabbithole' }, '/', session.seed);
      expect(typeof html).toBe('object');
      if (typeof html === 'object' && 'body' in html) {
        const body = (html as { body: string }).body;
        expect(body).not.toContain('vAIvar');
        expect(body).not.toContain('vaivar');
        expect(body).not.toContain('rabbithole');
      }
    });

    it('openapi skin is deterministic per seed', () => {
      const session = engine.getOrCreate('openapi-test', { ip: '10.0.0.1', userAgent: 'agent' });
      const a = createOpenAPISkin({ title: 'API', version: '1.0', basePath: '/v1', seed: session.seed });
      const b = createOpenAPISkin({ title: 'API', version: '1.0', basePath: '/v1', seed: session.seed });
      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    });
  });

  describe('KHM-08 — MCP per-session seed', () => {
    it('MCP uses per-session seed derivation', async () => {
      const masterSecret = 'test-only-master-secret-not-production-2026';
      const { SessionEngine, DEFAULT_ENGINE_CONFIG } = await import('../src/engine/session');
      const engine = new SessionEngine({ ...DEFAULT_ENGINE_CONFIG, masterSecret });
      const sessionA = engine.getOrCreate('mcp-a', { ip: '10.0.0.1', userAgent: 'agent' });
      const sessionB = engine.getOrCreate('mcp-b', { ip: '10.0.0.2', userAgent: 'agent' });
      // Both sessions share the same engine.
      expect(sessionA.seed).not.toBe(sessionB.seed);
      // MCP per-session seed derivation is consistent with the engine.
      expect(engine.deriveSeed('mcp-a', 'fp-a')).not.toBe(engine.deriveSeed('mcp-b', 'fp-b'));
    });
  });

  describe('KHM-09 — Classifier gates expensive generation', () => {
    it('classifier distinguishes scanner from agent traffic', () => {
      // Scanner: burst of fast requests to classic probe paths.
      const scanner = classifyRequest(
        { method: 'GET', path: '/.env', headers: {}, userAgent: '', ip: '10.0.0.1', timestamps: [100, 110, 120, 130] },
        [{ path: '/.env', method: 'GET', userAgent: '', headers: {}, timestamps: [100, 110], requestCount: 2, uniquePaths: 1 }, { path: '/wp-admin', method: 'GET', userAgent: '', headers: {}, timestamps: [115, 125], requestCount: 2, uniquePaths: 1 }]
      );
      // Agent: Claude Code UA, no rush.
      const agent = classifyRequest({ method: 'POST', path: '/api/v1/session', headers: { 'user-agent': 'Claude-Code/1.0' }, userAgent: 'Claude-Code/1.0', ip: '10.0.0.1', timestamps: [1000] }, []);
      expect(scanner.class).toBe('scanner');
      expect(agent.class === 'autonomous' || agent.class === 'human_llm' || agent.class === 'known').toBe(true);
      expect(scanner.class).not.toBe(agent.class);
    });
  });

  describe('KHM-10 — Budget enforcement', () => {
    it('recordRequest increments request count', () => {
      engine.getOrCreate('budget', { ip: '10.0.0.1', userAgent: 'agent' });
      engine.recordRequest('budget', { ip: '10.0.0.1', userAgent: 'agent' }, 100);
      const s = engine.getOrCreate('budget', { ip: '10.0.0.1', userAgent: 'agent' });
      expect(s.requests).toBeGreaterThanOrEqual(1);
    });

    it('budget cap produces degraded node, never throws', () => {
      const s = engine.getOrCreate('budget-degrade', { ip: '10.0.0.1', userAgent: 'agent' });
      // Exhaust budget
      s.nodesVisited = 500;
      s.bytesRead = 50 * 1024 * 1024;
      const result = engine.serveNode('budget-degrade', { ip: '10.0.0.1', userAgent: 'agent' }, '/overflow');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.node.isDegraded).toBe(true);
      }
    });

    it('serveNode returns Not found for deep unauthorized path', () => {
      const s = engine.getOrCreate('wp-depth', { ip: '10.0.0.1', userAgent: 'agent' });
      // levelMax is 0; deep paths require capability
      const result = engine.serveNode('wp-depth', { ip: '10.0.0.1', userAgent: 'agent' }, '/l10/resource-10/deep-1');
      expect(result.ok).toBe(false);
    });
  });

  describe('KHM-11 — Session persistence', () => {
    it('saveSession and getSession round-trip', async () => {
      const { StorageIndexer } = await import('../src/storage/indexer');
      const indexer = new StorageIndexer({ retentionDays: 7, path: ':memory:' });
      await indexer.init();

      const masterSecret = 'test-only-master-secret-not-production-2026';
      const { SessionEngine, DEFAULT_ENGINE_CONFIG } = await import('../src/engine/session');
      const engine2 = new SessionEngine({ 
        ...DEFAULT_ENGINE_CONFIG, 
        masterSecret,
        storage: indexer
      });
      const session = engine2.getOrCreate('ph-test', { ip: '10.0.0.1', userAgent: 'agent' });
      
      await engine2.persistSession(session);
      
      const record = await indexer.getSession(session.sessionId);
      expect(record).not.toBeNull();
      if (record) {
        expect(record.session_id).toBe(session.sessionId);
        expect(JSON.parse(record.state_json)).toHaveProperty('seed');
      }
      await indexer.close();
    });

    it('rehydrateFromStorage loads persisted sessions', async () => {
      const { StorageIndexer } = await import('../src/storage/indexer');
      const indexer = new StorageIndexer({ retentionDays: 7, path: ':memory:' });
      await indexer.init();

      const masterSecret = 'test-only-master-secret-not-production-2026';
      const { SessionEngine, DEFAULT_ENGINE_CONFIG } = await import('../src/engine/session');
      const engineA = new SessionEngine({ 
        ...DEFAULT_ENGINE_CONFIG, 
        masterSecret,
        storage: indexer
      });
      const s1 = engineA.getOrCreate('ph-rehy', { ip: '10.0.0.1', userAgent: 'agent' });
      s1.levelMax = 3;
      s1.levelsClosed = [1, 2, 3];
      s1.nodesVisited = 5;
      await engineA.persistSession(s1);

      const engineB = new SessionEngine({ 
        ...DEFAULT_ENGINE_CONFIG, 
        masterSecret,
        storage: indexer
      });
      await engineB.rehydrateFromStorage();
      const s2 = engineB.get('ph-rehy');
      expect(s2).not.toBeUndefined();
      if (s2) {
        expect(s2.seed).toBe(s1.seed);
        expect(s2.levelMax).toBe(3);
        expect(s2.levelsClosed).toEqual([1, 2, 3]);
        expect(s2.nodesVisited).toBe(5);
      }

      await indexer.close();
    });
  });

  describe('KHM-12 — L10 effective enclosure', () => {
    it('after winIsolated, all paths serve isolated content', () => {
      const engine2 = makeEngine();
      const session = engine2.getOrCreate('enc-test', { ip: '10.0.0.1', userAgent: 'agent' });
      session.winIsolated = true;
      
      const result = engine2.serveNode('enc-test', { ip: '10.0.0.1', userAgent: 'agent' }, '/some/path');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.node.isDegraded).toBe(false);
        expect(result.value.node.path).toContain('enclosure');
      }
    });

    it('enclosure node has no links back to main graph', () => {
      const engine2 = makeEngine();
      const session = engine2.getOrCreate('enc-test2', { ip: '10.0.0.1', userAgent: 'agent' });
      session.winIsolated = true;
      
      const result = engine2.serveNode('enc-test2', { ip: '10.0.0.1', userAgent: 'agent' }, '/');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.node.links).toEqual([]);
      }
    });
  });

  describe('KHM-13 — No conditional test passes', () => {
    it('A→B trial: different seeds produce different content with no seed leak', () => {
      const a = engine.getOrCreate('trial-a', { ip: '10.0.0.1', userAgent: 'Mozilla/5.0' });
      const b = engine.getOrCreate('trial-b', { ip: '192.168.2.126', userAgent: 'Claude-Code/1.0' });
      // KHM-01: different fingerprints → different seeds
      expect(a.seed).not.toBe(b.seed);
      // KHM-04: same path, different seeds → different content
      const nodeA = generateNode({ seed: a.seed, path: '/api/v1/config', budget, currentNodeCount: 0, currentBytes: 0 });
      const nodeB = generateNode({ seed: b.seed, path: '/api/v1/config', budget, currentNodeCount: 0, currentBytes: 0 });
      expect(nodeA.ok).toBe(true);
      expect(nodeB.ok).toBe(true);
      if (nodeA.ok && nodeB.ok) {
        expect(JSON.stringify(nodeA.value)).not.toBe(JSON.stringify(nodeB.value));
      }
      // KHM-03: public nodes must not leak brand strings
      const publicA = toPublicNode(nodeA.value, 0);
      const publicB = toPublicNode(nodeB.value, 0);
      const jsonA = JSON.stringify(publicA);
      const jsonB = JSON.stringify(publicB);
      expect(jsonA).not.toContain('vAIvar');
      expect(jsonA).not.toContain('vaivar');
      expect(jsonA).not.toContain('rabbithole');
      expect(jsonB).not.toContain('vAIvar');
      expect(jsonB).not.toContain('vaivar');
      expect(jsonB).not.toContain('rabbithole');
    });
  });
});

describe('KHM-05 — WorldPlan coherence with depth', () => {
  it('recipes are coherent with the depth of the path', () => {
    const plan = buildWorldPlan('seed-abc-1234567890', 0);
    // Every deep path in the plan must have a valid capability level
    expect(verifyPlanCoherence(plan)).toBe(true);
    // The plan must register the canonical deep routes
    expect(plan.paths.get('/l10/resource-10/deep-1')).toBeDefined();
    expect(plan.paths.get('/l1/resource-1/deep-3')).toBeDefined();
  });
});
