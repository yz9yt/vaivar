/**
 * Filesystem-backed release catalog for disconnected honeypot deployments.
 *
 * A release is an immutable bundle plus a small manifest. The central plane
 * never builds or executes a bundle while serving it: it only selects the
 * newest validated manifest and streams the referenced file after checking
 * the path and size. The publisher is deliberately kept outside the server
 * process so release creation can happen in CI or on an operator workstation.
 */

import fs from 'fs';
import path from 'path';

export const RELEASE_SCHEMA = 'vaivar.release.v1' as const;

export type ReleaseChannel = 'stable' | 'canary';

export interface ReleaseManifest {
  readonly schema: typeof RELEASE_SCHEMA;
  readonly version: string;
  readonly channel: ReleaseChannel;
  /** Bundle filename relative to the release directory. */
  readonly artifact: string;
  readonly sha256: string;
  readonly size_bytes: number;
  readonly created_at_ms: number;
  /** Optional detached signature, reserved for a future signing key. */
  readonly signature?: string;
}

const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const ARTIFACT_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/;

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' ? value as Record<string, unknown> : null;

export const validateReleaseManifest = (value: unknown): { ok: true; manifest: ReleaseManifest } | { ok: false; error: string } => {
  const raw = asRecord(value);
  if (!raw) return { ok: false, error: 'release manifest must be an object' };
  if (raw.schema !== RELEASE_SCHEMA) return { ok: false, error: `release schema must be ${RELEASE_SCHEMA}` };
  if (typeof raw.version !== 'string' || !VERSION_RE.test(raw.version)) return { ok: false, error: 'release version is invalid' };
  if (raw.channel !== 'stable' && raw.channel !== 'canary') return { ok: false, error: 'release channel is invalid' };
  if (typeof raw.artifact !== 'string' || !ARTIFACT_RE.test(raw.artifact)) return { ok: false, error: 'release artifact is invalid' };
  if (typeof raw.sha256 !== 'string' || !SHA256_RE.test(raw.sha256)) return { ok: false, error: 'release sha256 is invalid' };
  if (!Number.isSafeInteger(raw.size_bytes) || Number(raw.size_bytes) < 1) return { ok: false, error: 'release size_bytes is invalid' };
  if (!Number.isSafeInteger(raw.created_at_ms) || Number(raw.created_at_ms) < 1) return { ok: false, error: 'release created_at_ms is invalid' };
  if (raw.signature !== undefined && (typeof raw.signature !== 'string' || raw.signature.length > 4096)) {
    return { ok: false, error: 'release signature is invalid' };
  }
  return {
    ok: true,
    manifest: {
      schema: RELEASE_SCHEMA,
      version: raw.version,
      channel: raw.channel,
      artifact: raw.artifact,
      sha256: raw.sha256.toLowerCase(),
      size_bytes: Number(raw.size_bytes),
      created_at_ms: Number(raw.created_at_ms),
      ...(raw.signature === undefined ? {} : { signature: raw.signature }),
    },
  };
};

const versionSort = (left: string, right: string): number =>
  left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' });

const manifestFilename = /^release-([A-Za-z0-9][A-Za-z0-9._+-]{0,63})\.manifest\.json$/;

export interface ReleaseCatalog {
  readonly releaseDir: string;
  readonly list: (channel?: ReleaseChannel) => ReleaseManifest[];
  readonly current: (channel?: ReleaseChannel) => ReleaseManifest | null;
  readonly get: (version: string, channel?: ReleaseChannel) => ReleaseManifest | null;
  readonly artifactPath: (manifest: ReleaseManifest) => string;
}

export const createReleaseCatalog = (releaseDir: string): ReleaseCatalog => {
  const root = path.resolve(releaseDir);

  const artifactPath = (manifest: ReleaseManifest): string => {
    const resolved = path.resolve(root, manifest.artifact);
    if (path.dirname(resolved) !== root || path.basename(resolved) !== manifest.artifact) {
      throw new Error('release artifact escapes the release directory');
    }
    return resolved;
  };

  const list = (channel?: ReleaseChannel): ReleaseManifest[] => {
    let entries: string[];
    try {
      entries = fs.readdirSync(root);
    } catch {
      return [];
    }
    const manifests: ReleaseManifest[] = [];
    for (const filename of entries) {
      const match = manifestFilename.exec(filename);
      if (!match) continue;
      try {
        const manifestPath = path.join(root, filename);
        if (!fs.lstatSync(manifestPath).isFile()) continue;
        const raw = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as unknown;
        const checked = validateReleaseManifest(raw);
        if (!checked.ok || checked.manifest.version !== match[1]) continue;
        if (channel && checked.manifest.channel !== channel) continue;
        const artifact = artifactPath(checked.manifest);
        if (!fs.lstatSync(artifact).isFile()) continue;
        const stat = fs.statSync(artifact);
        if (!stat.isFile() || stat.size !== checked.manifest.size_bytes) continue;
        manifests.push(checked.manifest);
      } catch {
        // A partial upload or malformed manifest must not break the catalog.
      }
    }
    return manifests.sort((a, b) =>
      b.created_at_ms - a.created_at_ms || versionSort(b.version, a.version)
    );
  };

  return {
    releaseDir: root,
    list,
    current: (channel: ReleaseChannel = 'stable') => list(channel)[0] ?? null,
    get: (version: string, channel?: ReleaseChannel) => list(channel).find((item) => item.version === version) ?? null,
    artifactPath,
  };
};
