import type { HoneypotProfile } from '../node/config';
import { TEMPLATE_SCHEMA, type HoneypotTemplate, validateHoneypotTemplate } from './types';

const template = (
  id: string,
  profile: HoneypotProfile,
  name: string,
  title: string,
  description: string,
  pages: HoneypotTemplate['pages']
): HoneypotTemplate => {
  const result = validateHoneypotTemplate({
    schema: TEMPLATE_SCHEMA,
    id,
    version: 1,
    profile,
    name,
    title,
    description,
    accent: '#4f46e5',
    pages,
  });
  if (!result.ok) throw new Error(`Invalid built-in template: ${result.error}`);
  return result.template;
};

const wikiPages = [
  {
    path: '/',
    title: 'Operations Knowledge Base',
    content: 'Welcome to the internal knowledge base. Browse the handbook, service status and operational notes.',
    links: [
      { label: 'Handbook', path: '/wiki/handbook' },
      { label: 'Service status', path: '/wiki/status' },
    ],
  },
  {
    path: '/wiki/',
    title: 'Operations Knowledge Base',
    content: 'Welcome to the internal knowledge base. Browse the handbook, service status and operational notes.',
    links: [
      { label: 'Handbook', path: '/wiki/handbook' },
      { label: 'Service status', path: '/wiki/status' },
    ],
  },
  {
    path: '/wiki/handbook',
    title: 'Employee Handbook',
    content: 'Teams use this handbook for onboarding, support procedures and day-to-day service operations.',
    links: [{ label: 'Back to home', path: '/wiki/' }],
  },
  {
    path: '/wiki/home',
    title: 'Operations Knowledge Base',
    content: 'Welcome to the internal knowledge base. Browse the handbook, service status and operational notes.',
    links: [
      { label: 'Handbook', path: '/wiki/handbook' },
      { label: 'Service status', path: '/wiki/status' },
    ],
  },
  {
    path: '/wiki/status',
    title: 'Service Status',
    content: 'All internal services are monitored continuously. Review the maintenance calendar before making changes.',
    links: [{ label: 'Back to home', path: '/wiki/' }],
  },
] as const;

const httpPages = [
  {
    path: '/',
    title: 'Customer API Gateway',
    content: 'Welcome to the customer API gateway. Review the API documentation and service status before integrating.',
    links: [
      { label: 'API documentation', path: '/openapi.json' },
      { label: 'Status', path: '/status' },
    ],
  },
  {
    path: '/status',
    title: 'Service Status',
    content: 'The API gateway is operating normally. Scheduled maintenance is published to registered customers.',
    links: [{ label: 'Back to home', path: '/' }],
  },
] as const;

const openApiPages = [
  {
    path: '/',
    title: 'Developer API',
    content: 'Welcome to the developer API portal. The machine-readable contract is available at the OpenAPI endpoint.',
    links: [{ label: 'OpenAPI document', path: '/openapi.json' }],
  },
] as const;

const mcpPages = [
  {
    path: '/',
    title: 'Tool Gateway',
    content: 'This gateway provides tools for connected assistants and internal automation clients.',
    links: [{ label: 'Service information', path: '/tools' }],
  },
  {
    path: '/tools',
    title: 'Available Tools',
    content: 'Tool discovery is available to compatible clients through the service gateway.',
    links: [{ label: 'Back to home', path: '/' }],
  },
] as const;

export const createDefaultTemplate = (profile: HoneypotProfile): HoneypotTemplate => {
  switch (profile) {
    case 'wiki':
      return template('wiki-starter', profile, 'Wiki starter', 'Operations Knowledge Base', 'A useful internal documentation surface.', wikiPages);
    case 'http':
      return template('http-starter', profile, 'HTTP starter', 'Customer API Gateway', 'A useful customer-facing API surface.', httpPages);
    case 'openapi':
      return template('openapi-starter', profile, 'OpenAPI starter', 'Developer API', 'A useful developer documentation surface.', openApiPages);
    case 'mcp':
      return template('mcp-starter', profile, 'MCP starter', 'Tool Gateway', 'A useful tool-service surface.', mcpPages);
    case 'all':
    default:
      return template('all-starter', profile, 'Service portal starter', 'Internal Service Portal', 'A useful multi-surface landing page.', [
        ...wikiPages,
        ...httpPages.filter((page) => page.path !== '/'),
      ]);
  }
};

export const DEFAULT_TEMPLATES: readonly HoneypotTemplate[] = [
  createDefaultTemplate('all'),
  createDefaultTemplate('http'),
  createDefaultTemplate('wiki'),
  createDefaultTemplate('openapi'),
  createDefaultTemplate('mcp'),
];
