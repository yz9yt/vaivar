/**
 * Application-level encryption for the Central ↔ honeypot control channel.
 *
 * The socket may be plain HTTP. Sensitive request and response bodies are
 * sealed with AES-256-GCM using a key derived from the deployment-specific
 * barrier token. The token is a pre-shared secret: it is never placed in an
 * HTTP header or sent over the wire. GCM authenticates the envelope as well
 * as encrypting it, so a captured or modified packet is not useful to an
 * observer or man-in-the-middle.
 */

import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

export const CONTROL_CHANNEL_VERSION = 'vaivar.control.v1';
export const CONTROL_CHANNEL_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const CONTROL_CHANNEL_MAX_PLAINTEXT_BYTES = 5 * 1024 * 1024;

export type ControlChannelDirection = 'request' | 'response';

export interface ControlEnvelope {
  readonly protocol: typeof CONTROL_CHANNEL_VERSION;
  readonly direction: ControlChannelDirection;
  readonly request_id: string;
  readonly timestamp_ms: number;
  readonly nonce: string;
  readonly iv: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export interface ControlRequest {
  readonly method: 'GET' | 'POST';
  /** Relative route, including its query string when needed. */
  readonly url: string;
  readonly body?: string;
}

export interface ControlResponse {
  readonly status: number;
  readonly body: string;
}

const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const NONCE_LENGTH = 24;

const encode = (value: Buffer): string => value.toString('base64url');

const decode = (value: unknown, maxLength: number): Buffer => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid control-channel binary field');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length === 0 || decoded.length > maxLength) {
    throw new Error('Invalid control-channel binary field length');
  }
  return decoded;
};

const validateRequestId = (value: unknown): string => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(value)) {
    throw new Error('Invalid control-channel request id');
  }
  return value;
};

const validateTimestamp = (value: unknown, nowMs: number): number => {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) ||
    Math.abs(nowMs - value) > CONTROL_CHANNEL_MAX_CLOCK_SKEW_MS) {
    throw new Error('Expired control-channel message');
  }
  return value;
};

const deriveAad = (
  direction: ControlChannelDirection,
  requestId: string,
  timestampMs: number,
  nonce: string,
): Buffer => Buffer.from(
  `${CONTROL_CHANNEL_VERSION}|${direction}|${requestId}|${timestampMs}|${nonce}`,
  'utf8'
);

/** Derive the fixed per-deployment control key from the shared barrier token. */
export const deriveControlKey = (token: string): Buffer => {
  if (typeof token !== 'string' || token.length < 16) {
    throw new Error('Control-channel token is too short');
  }
  return Buffer.from(hkdfSync(
    'sha256',
    Buffer.from(token, 'utf8'),
    Buffer.from('vaivar.control.psk.v1', 'utf8'),
    Buffer.from('aes-256-gcm', 'utf8'),
    KEY_LENGTH,
  ));
};

export const sealControlMessage = (
  key: Buffer,
  direction: ControlChannelDirection,
  requestId: string,
  payload: unknown,
  timestampMs = Date.now(),
): ControlEnvelope => {
  validateRequestId(requestId);
  if (!Number.isSafeInteger(timestampMs)) throw new Error('Invalid control-channel timestamp');
  const nonce = encode(randomBytes(NONCE_LENGTH));
  const aad = deriveAad(direction, requestId, timestampMs, nonce);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  if (plaintext.length > CONTROL_CHANNEL_MAX_PLAINTEXT_BYTES) {
    throw new Error('Control-channel payload is too large');
  }
  const actualIv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, actualIv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    protocol: CONTROL_CHANNEL_VERSION,
    direction,
    request_id: requestId,
    timestamp_ms: timestampMs,
    nonce,
    iv: encode(actualIv),
    ciphertext: encode(ciphertext),
    tag: encode(cipher.getAuthTag()),
  };
};

/** Open and authenticate one control-channel message. */
export const openControlMessage = <T>(
  key: Buffer,
  direction: ControlChannelDirection,
  raw: unknown,
  nowMs = Date.now(),
): { requestId: string; timestampMs: number; nonce: string; payload: T } => {
  if (!raw || typeof raw !== 'object') throw new Error('Invalid control-channel envelope');
  const envelope = raw as Partial<ControlEnvelope>;
  if (envelope.protocol !== CONTROL_CHANNEL_VERSION || envelope.direction !== direction) {
    throw new Error('Invalid control-channel protocol');
  }
  const requestId = validateRequestId(envelope.request_id);
  const timestampMs = validateTimestamp(envelope.timestamp_ms, nowMs);
  const nonce = decode(envelope.nonce, NONCE_LENGTH);
  if (nonce.length !== NONCE_LENGTH) throw new Error('Invalid control-channel nonce');
  const iv = decode(envelope.iv, IV_LENGTH);
  if (iv.length !== IV_LENGTH) throw new Error('Invalid control-channel IV');
  const ciphertext = decode(envelope.ciphertext, CONTROL_CHANNEL_MAX_PLAINTEXT_BYTES);
  const tag = decode(envelope.tag, TAG_LENGTH);
  if (tag.length !== TAG_LENGTH) throw new Error('Invalid control-channel tag');
  const nonceText = envelope.nonce as string;
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(deriveAad(direction, requestId, timestampMs, nonceText));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (plaintext.length > CONTROL_CHANNEL_MAX_PLAINTEXT_BYTES) {
    throw new Error('Control-channel payload is too large');
  }
  let payload: T;
  try {
    payload = JSON.parse(plaintext.toString('utf8')) as T;
  } catch {
    throw new Error('Invalid control-channel JSON payload');
  }
  return { requestId, timestampMs, nonce: nonceText, payload };
};

export const controlEnvelopeReplayKey = (requestId: string, nonce: string): string => `${requestId}:${nonce}`;
