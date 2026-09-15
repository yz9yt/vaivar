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

// Central secret store: encrypts node barrier tokens with a central-specific
// key so the operator list API never returns plaintext credentials. The key
// is independent of any honeypot token and must be generated once and
// persisted by the operator. AAD binds each ciphertext to its site id so a
// record cannot be re-encrypted under a different node.

import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from 'crypto';

export const SECRET_STORE_VERSION = 'secret.v1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;

/** Derive a stable 256-bit AES key from the master secret + service name. */
export const deriveKey = (masterSecret: string, service: string): Buffer =>
  scryptSync(masterSecret, `vaivar|${service}`, 32, { N: 16384, r: 8, p: 1 });

export interface EncryptedSecret {
  readonly version: typeof SECRET_STORE_VERSION;
  readonly ciphertext: string;
  readonly iv: string;
  readonly tag: string;
}

/**
 * Encrypt a secret with AES-256-GCM. The additional authenticated data (AAD)
 * binds the ciphertext to its purpose so it cannot be replayed elsewhere.
 */
export const encryptSecret = (key: Buffer, plaintext: string, aad: string): EncryptedSecret => {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    version: SECRET_STORE_VERSION,
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
  };
};

/** Decrypt, or throw when the key/AAD does not match (authentication failed). */
export const decryptSecret = (key: Buffer, secret: EncryptedSecret, aad: string): string => {
  if (secret.version !== SECRET_STORE_VERSION) {
    throw new Error(`Unsupported secret version: ${secret.version}`);
  }
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(secret.iv, 'hex'));
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(secret.tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(secret.ciphertext, 'hex')), decipher.final()]).toString('utf8');
};

/**
 * Deterministic fingerprint for equality checks without exposing the secret.
 * Returns a truncated SHA-256 of the token (8 hex chars).
 */
export const tokenFingerprint = (token: string): string =>
  createHash('sha256').update(token).digest('hex').slice(0, 8);
