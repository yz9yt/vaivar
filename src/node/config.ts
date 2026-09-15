/**
 * Runtime configuration for the public honeypot surface.
 *
 * The control API always remains on its own listener. A profile only selects
 * which deceptive public surface is enabled on the honeypot listener.
 */

export const HONEYPOT_PROFILES = ['all', 'http', 'wiki', 'openapi', 'mcp'] as const;

export type HoneypotProfile = (typeof HONEYPOT_PROFILES)[number];

export const DEFAULT_HONEYPOT_PROFILE: HoneypotProfile = 'all';

export const isHoneypotProfile = (value: unknown): value is HoneypotProfile =>
  typeof value === 'string' && (HONEYPOT_PROFILES as readonly string[]).includes(value);

export const normalizeHoneypotProfile = (value: unknown): HoneypotProfile =>
  isHoneypotProfile(value) ? value : DEFAULT_HONEYPOT_PROFILE;

export interface HoneypotRuntimeConfig {
  readonly honeypot_port: number;
  readonly service_profile: HoneypotProfile;
  readonly template?: import('../templates/types').HoneypotTemplate | null;
}
