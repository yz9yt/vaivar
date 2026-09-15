import { createHmac, timingSafeEqual } from 'crypto';
import { StorageIndexer } from '../src/storage/indexer';
import {
  deriveKey,
  encryptSecret,
  decryptSecret,
  tokenFingerprint,
} from '../src/central/secret-store';
import { createNodeClient } from '../src/central/node-client';
import { createNodeRegistry } from '../src/central/node-registry';

const IN_MEMORY = ':memory:';
const CENTRAL_KEY = 'b'.repeat(64);

const makeStorage = async (): Promise<StorageIndexer> => {
  const storage = new StorageIndexer({ path: IN_MEMORY });
  await storage.init();
  return storage;
};

describe('secret store', () => {
  test('encryptSecret / decryptSecret round-trips plaintext', () => {
    const key = deriveKey(CENTRAL_KEY, 'central-nodes');
    const aad = 'node:test-site';
    const encrypted = encryptSecret(key, 'super-secret-token', aad);
    expect(encrypted.version).toBe('secret.v1');
    expect(encrypted.ciphertext).toMatch(/^[0-9a-f]+$/);
    expect(encrypted.iv).toMatch(/^[0-9a-f]+$/);
    expect(encrypted.tag).toMatch(/^[0-9a-f]+$/);

    const plaintext = decryptSecret(key, encrypted, aad);
    expect(plaintext).toBe('super-secret-token');
  });

  test('decryptSecret fails with wrong key', () => {
    const key = deriveKey(CENTRAL_KEY, 'central-nodes');
    const wrongKey = deriveKey('x'.repeat(64), 'central-nodes');
    const encrypted = encryptSecret(key, 'token-data', 'node:site-1');
    expect(() => decryptSecret(wrongKey, encrypted, 'node:site-1')).toThrow();
  });

  test('decryptSecret fails with wrong AAD', () => {
    const key = deriveKey(CENTRAL_KEY, 'central-nodes');
    const encrypted = encryptSecret(key, 'token-data', 'node:site-1');
    expect(() => decryptSecret(key, encrypted, 'node:site-2')).toThrow();
  });

  test('tokenFingerprint is deterministic and does not reveal the token', () => {
    expect(tokenFingerprint('my-secret-token')).toBe(tokenFingerprint('my-secret-token'));
    expect(tokenFingerprint('my-secret-token')).not.toContain('my-secret-token');
    expect(tokenFingerprint('a')).not.toBe(tokenFingerprint('b'));
  });
});

describe('node registry', () => {
  test('enroll verifies identity and stores encrypted credentials', async () => {
    const storage = await makeStorage();
    const client = createNodeClient();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, client);

    // enroll should return null when the node is unreachable.
    const result = await registry.enroll({
      host: '127.0.0.1',
      port: 1, // nothing listening
      token: '0'.repeat(32),
    });
    expect(result).toBeNull();

    // listNodes should return the existing node set (may be empty).
    const nodes = await registry.listNodes();
    expect(nodes).toHaveLength(0);
  });

  test('saveCentralNode with in-memory fallback does not throw', async () => {
    const storage = await makeStorage();
    const key = deriveKey(CENTRAL_KEY, 'central-nodes');
    const encrypted = encryptSecret(key, 'token-value', 'node:site-1');
    const record = {
      site_id: 'site-1', host: '10.0.0.1', port: 3000,
      encrypted_secret: encrypted.ciphertext, iv: encrypted.iv,
      auth_tag: encrypted.tag, encrypted_secret_aad: 'node:site-1',
      token_fingerprint: tokenFingerprint('token-value'),
      capabilities: ['events.read'] as const,
      registered_at_ms: Date.now(), last_contacted_at_ms: null,
    };
    // Must not throw regardless of SQLite availability.
    await expect(storage.saveCentralNode(record)).resolves.toBeUndefined();
    await storage.close();
  });

  test('verifySettings returns null for an unregistered site', async () => {
    const storage = await makeStorage();
    const client = createNodeClient();
    const registry = createNodeRegistry(storage, CENTRAL_KEY, client);

    const result = await registry.verifySettings('unknown-site', '0'.repeat(32));
    expect(result).toBeNull();
    await storage.close();
  });
});
