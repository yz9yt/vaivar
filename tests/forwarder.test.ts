import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCentralServer } from '../src/central/server';
import { createRemoteEventSink } from '../src/central/forwarder';
import { StorageIndexer } from '../src/storage/indexer';
import { createSessionEvent } from '../src/types/events';

const INGEST_TOKEN = 'central-ingest-token-0123456789abcdef';

describe('encrypted edge event forwarding', () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'vaivar-forwarder-'));
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  test('sends an opaque HTTP envelope without the ingest token or event body', async () => {
    const storage = new StorageIndexer({ path: ':memory:' });
    await storage.init();
    const central = createCentralServer({
      port: 0,
      host: '127.0.0.1',
      storage,
      ingestToken: INGEST_TOKEN,
      operatorToken: 'operator-token-0123456789',
    });
    await central.listen();
    const address = central.server.address() as { port: number };
    const sink = createRemoteEventSink({
      url: `http://127.0.0.1:${address.port}`,
      token: INGEST_TOKEN,
      siteId: 'site-forwarded',
    });
    const event = createSessionEvent({
      sessionId: 'session-only-inside-ciphertext',
      seedId: 'seed-only-inside-ciphertext',
      src: { ip: '10.0.0.5', userAgent: 'test', headersInteresting: {} },
      agent: { class: 'unknown', tooling: [], confidence: 0 },
      progress: { level_max: 0, levels_closed: [], win_isolated: false, meta_detect: false },
      intent: { dwell_seconds: 1, requests: 1, retries: 0, returning_days: 0, bytes_read: 0, nodes_visited: 0 },
      scores: { capability: 0, intent: 0 },
      skins: ['http'],
      flagsFired: [],
      severityHint: 'info',
    });

    const originalFetch = globalThis.fetch;
    let capturedUrl = '';
    let capturedInit: RequestInit | undefined;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = String(input);
      capturedInit = init;
      return originalFetch(input, init);
    }) as typeof fetch;

    try {
      await sink.asSink().write(event);
      await sink.flush();
    } finally {
      globalThis.fetch = originalFetch;
      await central.close();
      await storage.close();
    }

    expect(capturedUrl).toContain('/api/v1/events/secure');
    expect(JSON.stringify(capturedInit?.headers ?? {})).not.toContain(INGEST_TOKEN);
    expect(String(capturedInit?.body ?? '')).not.toContain(INGEST_TOKEN);
    expect(String(capturedInit?.body ?? '')).not.toContain('session-only-inside-ciphertext');
    expect((await storage.getEvents('session-only-inside-ciphertext', 10))).toHaveLength(1);
  });
});
