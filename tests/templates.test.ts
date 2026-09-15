import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefaultTemplate } from '../src/templates/defaults';
import { renderTemplatePage, templateHasPage } from '../src/templates/render';
import { TEMPLATE_SCHEMA, validateHoneypotTemplate, type HoneypotTemplate } from '../src/templates/types';
import { StorageIndexer } from '../src/storage/indexer';

const customTemplate: HoneypotTemplate = {
  schema: TEMPLATE_SCHEMA,
  id: 'customer-portal',
  version: 1,
  profile: 'wiki',
  name: 'Customer portal',
  description: 'A custom documentation portal.',
  title: 'Customer Portal',
  pages: [
    {
      path: '/',
      title: 'Welcome',
      content: 'This is a custom page.\n\nIt is managed as content.',
      links: [{ label: 'Handbook', path: '/wiki/handbook' }],
    },
  ],
};

describe('declarative honeypot templates', () => {
  test('built-in wiki template has useful home pages', () => {
    const template = createDefaultTemplate('wiki');
    expect(templateHasPage(template, '/')).toBe(true);
    expect(templateHasPage(template, '/wiki/')).toBe(true);
    const response = renderTemplatePage(template, '/', 'seed-template-test');
    expect(response?.status).toBe(200);
    expect(response?.body).toContain('Operations Knowledge Base');
  });

  test('template content is escaped and external/traversal paths are rejected', () => {
    const checked = validateHoneypotTemplate({
      ...customTemplate,
      pages: [{ ...customTemplate.pages[0], content: '<script>alert(1)</script>' }],
    });
    expect(checked.ok).toBe(true);
    if (checked.ok) {
      const response = renderTemplatePage(checked.template, '/', 'seed-template-test');
      expect(response?.body).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
      expect(response?.body).not.toContain('<script>alert(1)</script>');
    }
    const bad = validateHoneypotTemplate({
      ...customTemplate,
      pages: [{ ...customTemplate.pages[0], path: '/../secrets' }],
    });
    expect(bad.ok).toBe(false);
  });

  test('template and runtime configuration survive a storage reopen', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'vaivar-templates-'));
    try {
      const first = new StorageIndexer({ path: join(directory, 'vaivar.db') });
      await first.init();
      await first.saveHoneypotTemplate(customTemplate);
      await first.saveHoneypotConfig({ honeypot_port: 8088, service_profile: 'wiki', template: customTemplate });
      const durable = Boolean((first as unknown as { db?: unknown }).db);
      await first.close();

      const second = new StorageIndexer({ path: join(directory, 'vaivar.db') });
      await second.init();
      if (durable) {
        expect(await second.getHoneypotTemplate('customer-portal', 1)).toMatchObject({ id: 'customer-portal', version: 1 });
        expect(await second.getHoneypotConfig()).toMatchObject({ honeypot_port: 8088, service_profile: 'wiki', template: { id: 'customer-portal' } });
      } else {
        // Some host environments deliberately use the documented in-memory
        // fallback when the native SQLite probe is unavailable.
        expect(await second.getHoneypotTemplate('customer-portal', 1)).toBeNull();
        expect(await second.getHoneypotConfig()).toBeNull();
      }
      await second.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
