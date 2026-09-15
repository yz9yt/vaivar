import type { Response } from '../types/common';
import { checkNoBrandStrings, sanitizeBrandStrings } from '../skins/validators';
import { deriveServerHeaders } from '../skins/wiki';
import { normalizeTemplatePath, type HoneypotTemplate, type TemplatePage } from './types';

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const renderText = (value: string): string => value
  .split(/\n{2,}/)
  .filter((part) => part.trim().length > 0)
  .map((part) => `<p>${escapeHtml(part.trim()).replace(/\n/g, '<br>')}</p>`)
  .join('');

const findPage = (template: HoneypotTemplate, path: string): TemplatePage | null => {
  const requested = normalizeTemplatePath(path);
  const exact = template.pages.find((page) => normalizeTemplatePath(page.path) === requested);
  if (exact) return exact;
  if (requested === '/wiki' || requested === '/wiki/') {
    return template.pages.find((page) => normalizeTemplatePath(page.path) === '/') ?? null;
  }
  return null;
};

export const templateHasPage = (template: HoneypotTemplate, path: string): boolean =>
  findPage(template, path) !== null;

export const renderTemplatePage = (
  template: HoneypotTemplate,
  path: string,
  seed: string
): Response | null => {
  const page = findPage(template, path);
  if (!page) return null;
  const title = sanitizeBrandStrings(page.title || template.title);
  const body = sanitizeBrandStrings(page.content);
  const accent = template.accent ?? '#4f46e5';
  const links = (page.links ?? []).map((link) =>
    `<li><a href="${escapeHtml(normalizeTemplatePath(link.path))}">${escapeHtml(sanitizeBrandStrings(link.label))}</a></li>`
  ).join('');
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <meta name="description" content="${escapeHtml(sanitizeBrandStrings(template.description))}">
  <style>
    :root{color-scheme:light}body{font-family:system-ui,-apple-system,sans-serif;max-width:920px;margin:0 auto;padding:2rem;color:#1f2937;line-height:1.6}
    header{border-bottom:3px solid ${accent};margin-bottom:2rem;padding-bottom:1rem}h1{margin:0;color:#111827}p{max-width:70ch;white-space:normal}
    a{color:${accent};text-decoration:none}a:hover{text-decoration:underline}ul{padding-left:1.25rem;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding-top:1rem;padding-bottom:1rem}
  </style>
</head>
<body>
  <header><h1>${escapeHtml(title)}</h1></header>
  <main>${renderText(body)}${links ? `<nav aria-label="Related pages"><ul>${links}</ul></nav>` : ''}</main>
</body>
</html>`;
  const response: Response = {
    status: 200,
    headers: { ...deriveServerHeaders(seed, 'template') , 'Content-Type': 'text/html; charset=utf-8' },
    body: html,
  };
  const brandCheck = checkNoBrandStrings(response);
  return brandCheck.ok ? response : { ...response, body: sanitizeBrandStrings(response.body) };
};
