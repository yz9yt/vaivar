import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export type SupportedLocale = string;
export type TranslationSet = Record<string, string>;
export type TranslationBundle = Record<SupportedLocale, TranslationSet>;

const LANG_DIR = join(process.cwd(), 'langs');

export function loadTranslations(): TranslationBundle {
  const result: TranslationBundle = {};
  if (!existsSync(LANG_DIR)) return result;
  for (const file of readdirSync(LANG_DIR)) {
    if (!file.endsWith('.txt')) continue;
    const locale = file.replace(/\.txt$/, '');
    const content = readFileSync(join(LANG_DIR, file), 'utf-8');
    const set: TranslationSet = {};
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(';')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const value = trimmed.slice(eq + 1).trim();
      if (key) set[key] = value;
    }
    result[locale] = set;
  }
  return result;
}

export function listLocales(): SupportedLocale[] {
  if (!existsSync(LANG_DIR)) return [];
  return readdirSync(LANG_DIR)
    .filter((f) => f.endsWith('.txt'))
    .map((f) => f.replace(/\.txt$/, ''))
    .sort();
}
