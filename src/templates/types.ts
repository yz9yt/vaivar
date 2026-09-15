/**
 * Declarative public-surface templates.
 *
 * Templates are content, not executable code. The node validates the schema
 * before persisting or serving it, and the renderer escapes every value into
 * HTML. This keeps operator-controlled deception content separate from the
 * honeypot runtime and prevents a template from becoming a code execution or
 * SSRF channel.
 */

import { isHoneypotProfile, type HoneypotProfile } from '../node/config';

export const TEMPLATE_SCHEMA = 'vaivar.template.v1' as const;

export interface TemplateLink {
  readonly label: string;
  readonly path: string;
}

export interface TemplatePage {
  /** Absolute local path, for example `/` or `/wiki/handbook`. */
  readonly path: string;
  readonly title: string;
  /** Plain text/Markdown-like content. It is escaped before rendering. */
  readonly content: string;
  readonly links?: readonly TemplateLink[];
}

export interface HoneypotTemplate {
  readonly schema: typeof TEMPLATE_SCHEMA;
  readonly id: string;
  readonly version: number;
  /** Surface this template is designed for. `all` is compatible everywhere. */
  readonly profile: HoneypotProfile;
  readonly name: string;
  readonly description: string;
  readonly title: string;
  readonly accent?: string;
  readonly pages: readonly TemplatePage[];
}

export type TemplateValidation =
  | { readonly ok: true; readonly template: HoneypotTemplate }
  | { readonly ok: false; readonly error: string };

const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const ACCENT_RE = /^#[0-9a-f]{6}$/i;
const MAX_PAGES = 100;
const MAX_LINKS = 32;
const MAX_TITLE = 160;
const MAX_NAME = 120;
const MAX_DESCRIPTION = 1000;
const MAX_CONTENT = 20_000;

export const normalizeTemplatePath = (value: string): string => {
  const raw = value.trim().split(/[?#]/, 1)[0] || '/';
  const withLeadingSlash = raw.startsWith('/') ? raw : `/${raw}`;
  const normalized = withLeadingSlash.replace(/\\/g, '/').replace(/\/+/g, '/');
  const withoutTraversal = normalized
    .split('/')
    .filter((segment) => segment !== '' && segment !== '.')
    .join('/');
  return withoutTraversal ? `/${withoutTraversal}` : '/';
};

const isSafeTemplatePath = (value: string): boolean => {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 240 || trimmed.includes('\\') || /(^|\/)\.\.($|\/)/.test(trimmed)) return false;
  return trimmed.startsWith('/');
};

const asString = (value: unknown, max: number): string | null => {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > max) return null;
  return value.trim();
};

/** Validate and normalize untrusted template JSON from Central or a deploy file. */
export const validateHoneypotTemplate = (value: unknown): TemplateValidation => {
  if (!value || typeof value !== 'object') return { ok: false, error: 'template must be an object' };
  const raw = value as Record<string, unknown>;
  if (raw.schema !== TEMPLATE_SCHEMA) return { ok: false, error: `template schema must be ${TEMPLATE_SCHEMA}` };
  if (typeof raw.id !== 'string' || !ID_RE.test(raw.id)) return { ok: false, error: 'template id is invalid' };
  if (!Number.isInteger(raw.version) || Number(raw.version) < 1 || Number(raw.version) > 1_000_000) {
    return { ok: false, error: 'template version must be a positive integer' };
  }
  if (!isHoneypotProfile(raw.profile)) return { ok: false, error: 'template profile is invalid' };
  const name = asString(raw.name, MAX_NAME);
  const description = asString(raw.description, MAX_DESCRIPTION);
  const title = asString(raw.title, MAX_TITLE);
  if (!name || !description || !title) return { ok: false, error: 'template name, description and title are required' };
  if (raw.accent !== undefined && (typeof raw.accent !== 'string' || !ACCENT_RE.test(raw.accent))) {
    return { ok: false, error: 'template accent must be a hex color' };
  }
  if (!Array.isArray(raw.pages) || raw.pages.length < 1 || raw.pages.length > MAX_PAGES) {
    return { ok: false, error: `template pages must contain between 1 and ${MAX_PAGES} items` };
  }

  const seen = new Set<string>();
  const pages: TemplatePage[] = [];
  for (const item of raw.pages) {
    if (!item || typeof item !== 'object') return { ok: false, error: 'template page must be an object' };
    const page = item as Record<string, unknown>;
    if (typeof page.path !== 'string' || !isSafeTemplatePath(page.path)) return { ok: false, error: 'template page path is invalid' };
    const pagePath = normalizeTemplatePath(page.path);
    if (seen.has(pagePath)) return { ok: false, error: `duplicate template page path: ${pagePath}` };
    seen.add(pagePath);
    const pageTitle = asString(page.title, MAX_TITLE);
    const content = typeof page.content === 'string' && page.content.length <= MAX_CONTENT ? page.content.trim() : null;
    if (!pageTitle || content === null) return { ok: false, error: 'template page title/content is invalid' };

    let links: TemplateLink[] | undefined;
    if (page.links !== undefined) {
      if (!Array.isArray(page.links) || page.links.length > MAX_LINKS) return { ok: false, error: 'template page links are invalid' };
      links = [];
      for (const linkValue of page.links) {
        if (!linkValue || typeof linkValue !== 'object') return { ok: false, error: 'template link must be an object' };
        const link = linkValue as Record<string, unknown>;
        const label = asString(link.label, 120);
        if (!label || typeof link.path !== 'string' || !isSafeTemplatePath(link.path)) {
          return { ok: false, error: 'template link label/path is invalid' };
        }
        links.push({ label, path: normalizeTemplatePath(link.path) });
      }
    }
    pages.push({ path: pagePath, title: pageTitle, content, ...(links ? { links } : {}) });
  }

  return {
    ok: true,
    template: {
      schema: TEMPLATE_SCHEMA,
      id: raw.id,
      version: Number(raw.version),
      profile: raw.profile,
      name,
      description,
      title,
      ...(raw.accent ? { accent: raw.accent } : {}),
      pages,
    },
  };
};

export const templateAppliesToProfile = (template: HoneypotTemplate, profile: HoneypotProfile): boolean =>
  template.profile === 'all' || profile === 'all' || template.profile === profile;
