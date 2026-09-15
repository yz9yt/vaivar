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

import { VAIVAR_VERSION, VAIVAR_CODENAME } from '../version';
import { VAIVAR_LOGO_URL } from '../branding';
import { loadTranslations, listLocales, type SupportedLocale, type TranslationBundle } from './i18n';

const TRANSLATIONS: TranslationBundle = loadTranslations();
const AVAILABLE_LOCALES: SupportedLocale[] = listLocales();
const FALLBACK_LOCALE = (AVAILABLE_LOCALES[0] || 'eng') as SupportedLocale;

function escapeServerHtml(val: unknown): string {
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export const renderCentralDashboardHTML = (version: string = VAIVAR_VERSION): string => {
  const safeVersion = escapeServerHtml(version);
  const safeCodename = escapeServerHtml(VAIVAR_CODENAME);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vAIvar Central Command Plane | AI Honeypot Defense</title>
  <link rel="icon" href="${VAIVAR_LOGO_URL}" type="image/svg+xml">
  <script>
    (function() {
      try {
        var theme = localStorage.getItem('vaivar-theme');
        if (theme === 'dark' || (!theme && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
          document.documentElement.setAttribute('data-theme', 'dark');
        } else {
          document.documentElement.setAttribute('data-theme', 'light');
        }
        if (localStorage.getItem('vaivar-sidebar-collapsed') === 'true') {
          document.documentElement.classList.add('preload-sidebar-collapsed');
        }
      } catch (e) {}
    })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      /* Brand & Actions */
      --color-primary: #6366f1;
      --color-primary-light: #818cf8;
      --color-accent: #ddd6fe;
      --color-accent-border: #c7d2fe;
      --color-primary-tint: #eef2ff;

      /* Pill / Tag Tokens */
      --pill-bg: #eef2ff;
      --pill-border: #c7d2fe;
      --pill-text: #4338ca;

      /* Surfaces & Layout */
      --color-bg: #f8fafc;
      --color-surface: #ffffff;
      --color-border: #e2e8f0;
      --color-border-strong: #cbd5e1;
      --color-border-muted: #94a3b8;

      /* Typography */
      --color-text-main: #1e293b;
      --color-text-muted: #475569;
      --color-text-dim: #94a3b8;

      /* Feedback: Success */
      --feedback-success-bg: #a7f3d0;
      --feedback-success-text: #065f46;
      --feedback-success-border: #6ee7b7;

      /* Feedback: Warning */
      --feedback-warning-bg: #fde68a;
      --feedback-warning-text: #92400e;
      --feedback-warning-border: #fcd34d;

      /* Feedback: Danger */
      --feedback-danger-bg: #fecdd3;
      --feedback-danger-text: #9f1239;
      --feedback-danger-border: #fca5a5;

      /* Feedback: Info */
      --feedback-info-bg: #bae6fd;
      --feedback-info-text: #075985;
      --feedback-info-border: #7dd3fc;

      /* System & Component Aliases */
      --bg: var(--color-bg);
      --bg-surface: var(--color-surface);
      --panel: var(--color-surface);
      --panel-hover: #f1f5f9;
      --panel-solid: var(--color-surface);
      --panel-elevated: #f8fafc;
      --border: var(--color-border);
      --border-strong: var(--color-border-strong);
      --border-glow: var(--color-primary);
      --text: var(--color-text-main);
      --text-soft: var(--color-text-muted);
      --text-dim: var(--color-text-dim);
      --cyan: var(--color-primary);
      --cyan-glow: #4f46e5;
      --teal: #10b981;
      --teal-soft: var(--feedback-success-text);
      --violet: var(--color-primary);
      --violet-soft: #4338ca;
      --amber: #d97706;
      --amber-soft: var(--feedback-warning-text);
      --red: #e11d48;
      --red-soft: var(--feedback-danger-text);
      --blue: #2563eb;
      --sidebar-w: 244px;
      --sidebar-rail: 64px;
      --radius-sm: 4px;
      --radius-md: 6px;
      --radius-lg: 8px;
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
      --shadow-md: 0 1px 3px 0 rgba(0, 0, 0, 0.06), 0 1px 2px -1px rgba(0, 0, 0, 0.04);
      --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.06), 0 4px 6px -4px rgba(0, 0, 0, 0.03);
    }

    /* Inverted Pastel SaaS Palette for Dark Mode (Neutral Dark Gray / Near-Black) */
    :root[data-theme="dark"] {
      /* Brand & Actions */
      --color-primary: #818cf8;
      --color-primary-light: #a5b4fc;
      --color-accent: rgba(99, 102, 241, 0.22);
      --color-accent-border: rgba(129, 140, 248, 0.3);
      --color-primary-tint: rgba(99, 102, 241, 0.15);

      /* Pill / Tag Tokens (Neutral dark gray near-black background, crisp border, high contrast readable text) */
      --pill-bg: #16161a;
      --pill-border: #2c2c34;
      --pill-text: #e4e4e7;

      /* Surfaces & Layout (Neutral very dark gray / almost black, no blue tint) */
      --color-bg: #09090b;
      --color-surface: #121215;
      --color-border: #222226;
      --color-border-strong: #333339;
      --color-border-muted: #494952;

      /* Typography (Neutral) */
      --color-text-main: #f4f4f5;
      --color-text-muted: #a1a1aa;
      --color-text-dim: #71717a;

      /* Feedback: Inverted pastel for dark surfaces */
      --feedback-success-bg: rgba(16, 185, 129, 0.16);
      --feedback-success-text: #34d399;
      --feedback-success-border: rgba(52, 211, 153, 0.3);

      --feedback-warning-bg: rgba(245, 158, 11, 0.16);
      --feedback-warning-text: #fbbf24;
      --feedback-warning-border: rgba(251, 191, 36, 0.3);

      --feedback-danger-bg: rgba(244, 63, 94, 0.16);
      --feedback-danger-text: #fb7185;
      --feedback-danger-border: rgba(251, 113, 133, 0.3);

      --feedback-info-bg: rgba(14, 165, 233, 0.16);
      --feedback-info-text: #38bdf8;
      --feedback-info-border: rgba(56, 189, 248, 0.3);

      /* System & Component Aliases */
      --panel-hover: #1c1c21;
      --panel-solid: #121215;
      --panel-elevated: #18181c;
      --cyan-glow: #818cf8;
      --violet-soft: #a5b4fc;
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.4);
      --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
      --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.6);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--color-bg);
      color: var(--color-text-main);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }
    ::selection { background: var(--color-accent); color: var(--color-text-main); }
    code, pre, .mono { font-family: 'JetBrains Mono', monospace; }

    /* Custom Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--color-bg); }
    ::-webkit-scrollbar-thumb { background: var(--color-border-strong); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--color-border-muted); }

    .skip-link {
      position: absolute;
      left: 8px;
      top: -40px;
      z-index: 300;
      background: var(--color-primary);
      color: #fff;
      padding: 8px 12px;
      border-radius: var(--radius-md);
      font-size: 0.8rem;
      font-weight: 600;
      text-decoration: none;
    }
    .skip-link:focus { top: 8px; }
    :focus-visible {
      outline: 2px solid var(--color-primary);
      outline-offset: 2px;
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }

    /* Layout */
    .app-shell {
      display: grid;
      grid-template-columns: var(--sidebar-w) 1fr;
      min-height: 100vh;
      transition: grid-template-columns 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    :root.preload-sidebar-collapsed .app-shell,
    .app-shell.sidebar-collapsed {
      grid-template-columns: var(--sidebar-rail) 1fr;
    }
    .nav-backdrop {
      display: none;
    }

    /* Sidebar */
    .sidebar {
      position: sticky;
      top: 0;
      height: 100vh;
      background: var(--color-surface);
      border-right: 1px solid var(--color-border);
      display: flex;
      flex-direction: column;
      padding: 20px 14px 18px;
      z-index: 40;
      overflow-y: auto;
      overflow-x: hidden;
      white-space: nowrap;
      transition: width 0.25s cubic-bezier(0.4, 0, 0.2, 1), padding 0.25s ease;
      width: var(--sidebar-w);
      box-sizing: border-box;
    }
    :root.preload-sidebar-collapsed .sidebar,
    .app-shell.sidebar-collapsed .sidebar {
      width: var(--sidebar-rail);
      padding-left: 10px;
      padding-right: 10px;
    }
    .brand-info,
    .nav-group-title,
    .nav-item a span,
    .nav-badge {
      transition: opacity 0.18s cubic-bezier(0.4, 0, 0.2, 1), transform 0.18s cubic-bezier(0.4, 0, 0.2, 1), max-width 0.22s cubic-bezier(0.4, 0, 0.2, 1);
      opacity: 1;
      transform: translateX(0);
      max-width: 170px;
      overflow: hidden;
      white-space: nowrap;
      display: inline-block;
      vertical-align: middle;
    }
    :root.preload-sidebar-collapsed .brand-info,
    :root.preload-sidebar-collapsed .nav-group-title,
    :root.preload-sidebar-collapsed .nav-item a span,
    :root.preload-sidebar-collapsed .nav-badge,
    .app-shell.sidebar-collapsed .brand-info,
    .app-shell.sidebar-collapsed .nav-group-title,
    .app-shell.sidebar-collapsed .nav-item a span,
    .app-shell.sidebar-collapsed .nav-badge {
      opacity: 0;
      transform: translateX(-6px);
      max-width: 0;
      margin: 0;
      padding: 0;
      pointer-events: none;
      visibility: hidden;
    }
    .sidebar-footer {
      margin-top: auto;
      padding-top: 16px;
      border-top: 1px solid var(--color-border);
      overflow: hidden;
      transition: opacity 0.18s cubic-bezier(0.4, 0, 0.2, 1), max-height 0.25s cubic-bezier(0.4, 0, 0.2, 1), padding 0.25s ease, margin 0.25s ease, border-color 0.25s ease;
      max-height: 200px;
      opacity: 1;
    }
    :root.preload-sidebar-collapsed .sidebar-footer,
    .app-shell.sidebar-collapsed .sidebar-footer {
      max-height: 0;
      opacity: 0;
      padding-top: 0;
      padding-bottom: 0;
      margin-top: 0;
      margin-bottom: 0;
      border-top-color: transparent;
      pointer-events: none;
      visibility: hidden;
    }
    :root.preload-sidebar-collapsed .nav-item a,
    .app-shell.sidebar-collapsed .nav-item a {
      justify-content: center;
      padding: 10px 0;
      gap: 0;
      border-left: 2px solid transparent;
      border-radius: var(--radius-md);
    }
    :root.preload-sidebar-collapsed .nav-item a.active,
    .app-shell.sidebar-collapsed .nav-item a.active {
      border-left: 2px solid transparent;
      background: var(--color-primary-tint);
    }
    :root.preload-sidebar-collapsed .sidebar-brand,
    .app-shell.sidebar-collapsed .sidebar-brand {
      justify-content: center;
      padding: 4px 0 18px;
      gap: 0;
    }
    :root.preload-sidebar-collapsed .brand-mark,
    .app-shell.sidebar-collapsed .brand-mark {
      width: 44px;
      height: 44px;
      min-width: 44px;
      min-height: 44px;
    }
    :root.preload-sidebar-collapsed .brand-mark img,
    .app-shell.sidebar-collapsed .brand-mark img {
      width: 44px;
      height: 44px;
    }
    .sidebar-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 4px 8px 18px;
      border-bottom: 1px solid var(--color-border);
      margin-bottom: 16px;
      flex-shrink: 0;
    }
    .brand-mark {
      width: 64px;
      height: 64px;
      min-width: 64px;
      min-height: 64px;
      background: transparent !important;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: none !important;
      border: none !important;
      padding: 0;
      text-decoration: none;
    }
    .brand-mark img { width: 64px; height: 64px; object-fit: contain; display: block; }
    .brand-info h1 {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--color-text-main);
      line-height: 1.2;
    }
    .brand-tag {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 0.62rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--pill-text);
      background: var(--pill-bg);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--pill-border);
      margin-top: 3px;
      font-family: 'JetBrains Mono', monospace;
    }
    .pill {
      display: inline-block;
      font-size: 0.62rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--color-border);
      font-family: 'JetBrains Mono', monospace;
    }
    .pill-user { color: var(--color-text); background: var(--color-surface); border-color: var(--color-border); }
    .pill-admin { color: #1e40af; background: #dbeafe; border-color: #93c5fd; }
    .pill-superadmin { color: #7c2d12; background: #fed7aa; border-color: #fdba74; }
    .btn-danger { color: #b91c1c; border-color: #fecaca; background: #fef2f2; }
    .btn-danger:hover { background: #fee2e2; }
    .creator-link {
      color: var(--color-primary);
      text-decoration: none;
      font-size: 0.68rem;
      font-weight: 600;
      font-family: 'JetBrains Mono', monospace;
    }
    .creator-link:hover { text-decoration: underline; }

    .nav-group-title {
      font-size: 0.64rem;
      font-weight: 700;
      color: var(--color-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      padding: 0 10px;
      margin-bottom: 8px;
      font-family: 'JetBrains Mono', monospace;
    }
    .nav-list { display: flex; flex-direction: column; gap: 4px; list-style: none; }
    .nav-item a {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 9px 12px;
      border-radius: var(--radius-md);
      color: var(--color-text-muted);
      text-decoration: none;
      font-size: 0.82rem;
      font-weight: 500;
      transition: all 0.15s ease;
      position: relative;
      cursor: pointer;
      border-left: 2px solid transparent;
    }
    .nav-item a svg { width: 16px; height: 16px; stroke: currentColor; flex-shrink: 0; }
    .nav-item a:hover {
      color: var(--color-text-main);
      background: var(--panel-hover);
    }
    .nav-item a.active {
      color: var(--color-primary);
      background: var(--color-primary-tint);
      border-left: 3px solid var(--color-primary);
      border-radius: 0 var(--radius-md) var(--radius-md) 0;
      font-weight: 600;
    }
    .nav-item a.active svg { color: var(--color-primary); }
    .nav-badge {
      margin-left: auto;
      font-size: 0.65rem;
      font-weight: 700;
      padding: 1px 7px;
      border-radius: 9999px;
      background: var(--pill-bg);
      border: 1px solid var(--pill-border);
      color: var(--pill-text);
      font-family: 'JetBrains Mono', monospace;
    }
    .nav-badge.alert {
      background: var(--feedback-warning-bg);
      border: 1px solid var(--feedback-warning-border);
      color: var(--feedback-warning-text);
    }
    .nav-badge.critical-alarm {
      background: #dc2626 !important;
      border: 1px solid #ef4444 !important;
      color: #ffffff !important;
      font-weight: 800;
      box-shadow: 0 0 10px rgba(239, 68, 68, 0.7);
      animation: alarmPulse 1.4s infinite;
    }
    .threat-status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.7rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.04em;
      text-decoration: none;
      cursor: default;
      transition: all 0.2s ease;
    }
    .threat-status-pill.normal {
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(52, 211, 153, 0.35);
      color: #34d399;
    }
    .threat-status-pill.alarm {
      background: #dc2626;
      border: 1px solid #ef4444;
      color: #ffffff;
      box-shadow: 0 0 14px rgba(239, 68, 68, 0.6);
      animation: alarmPulse 1.4s infinite;
      cursor: pointer;
    }
    .pulse-dot.red-alarm {
      background: #ef4444;
      box-shadow: 0 0 8px #ef4444;
      animation: alarmBlink 1s infinite;
    }
    @keyframes alarmPulse {
      0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
      50% { transform: scale(1.02); box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
      100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    @keyframes alarmBlink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }
    .kpi-card.under-attack {
      border-color: #ef4444 !important;
      box-shadow: 0 0 16px rgba(239, 68, 68, 0.25) !important;
    }
    .attention-banner.attack-alarm {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid #ef4444;
      box-shadow: 0 0 16px rgba(239, 68, 68, 0.2);
    }
    .attack-row {
      background: rgba(239, 68, 68, 0.1) !important;
      border-left: 3px solid #ef4444 !important;
    }
    .attack-row:hover {
      background: rgba(239, 68, 68, 0.16) !important;
    }
    .active-filter-indicator {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 0.75rem;
      color: var(--color-text-main);
      background: rgba(99, 102, 241, 0.15);
      border: 1px solid var(--color-primary);
      padding: 3px 10px;
      border-radius: var(--radius-md);
      font-family: 'JetBrains Mono', monospace;
    }
    .btn-clear-filter {
      background: var(--panel-hover);
      border: 1px solid var(--color-border-strong);
      color: var(--color-text-main);
      border-radius: var(--radius-sm);
      font-size: 0.72rem;
      padding: 2px 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-family: inherit;
      transition: all 0.15s ease;
    }
    .btn-clear-filter:hover {
      background: #ef4444;
      border-color: #dc2626;
      color: #ffffff;
    }

    /* Sidebar Footer */
    .sidebar-footer {
      margin-top: auto;
      padding-top: 16px;
      border-top: 1px solid var(--color-border);
    }
    .status-card {
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .status-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.7rem;
    }
    .status-label { color: var(--color-text-muted); }
    .status-val { font-weight: 600; color: var(--feedback-success-text); display: flex; align-items: center; gap: 6px; }
    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #10b981;
      display: inline-block;
    }

    /* Main Area */
    .main-wrap {
      display: flex;
      flex-direction: column;
      min-width: 0;
      min-height: 100vh;
      position: relative;
    }

    /* App Footer - Minimalist Flat Fixed */
    .app-footer {
      position: fixed;
      bottom: 0;
      left: var(--sidebar-w);
      right: 0;
      z-index: 25;
      background: var(--color-surface);
      border-top: 1px solid var(--color-border);
      box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.03);
      padding: 10px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
      font-size: 0.75rem;
      transition: left 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    :root.preload-sidebar-collapsed .app-footer,
    .app-shell.sidebar-collapsed .app-footer {
      left: var(--sidebar-rail);
    }
    .footer-col-left {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .footer-badge-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .footer-brand {
      font-weight: 700;
      color: var(--color-text-main);
      letter-spacing: -0.01em;
    }
    .footer-tag {
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: var(--pill-bg);
      border: 1px solid var(--pill-border);
      color: var(--pill-text);
    }
    .footer-meta {
      color: var(--color-text-muted);
      font-size: 0.72rem;
    }
    .footer-col-right {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }
    .footer-metric {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .footer-metric-lbl {
      color: var(--color-text-muted);
      font-size: 0.68rem;
      font-weight: 600;
      letter-spacing: 0.04em;
    }
    .footer-metric-val {
      color: var(--color-text-main);
      font-weight: 600;
    }
    .footer-metric-val.mono {
      color: var(--color-primary);
      font-size: 0.74rem;
      background: var(--color-bg);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--color-border);
    }
    .footer-metric-val.status-live {
      color: var(--feedback-success-text);
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .footer-sep {
      width: 1px;
      height: 14px;
      background: var(--color-border);
    }

    @media (max-width: 900px) {
      .app-footer {
        left: 0;
        flex-direction: column;
        align-items: flex-start;
        padding: 10px 16px;
        gap: 8px;
      }
      .footer-sep { display: none; }
    }

    /* Top Control Bar */
    .topbar {
      position: sticky;
      top: 0;
      z-index: 30;
      background: var(--color-surface);
      border-bottom: 1px solid var(--color-border);
      padding: 12px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .topbar-left {
      display: flex;
      align-items: center;
      gap: 14px;
      flex: 1;
      max-width: 500px;
    }
    .search-box {
      position: relative;
      width: 100%;
    }
    .search-box svg {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      width: 15px;
      height: 15px;
      stroke: var(--color-text-muted);
      pointer-events: none;
    }
    .search-input {
      width: 100%;
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      color: var(--color-text-main);
      padding: 8px 36px 8px 34px;
      border-radius: var(--radius-md);
      font-size: 0.8rem;
      font-family: 'JetBrains Mono', monospace;
      outline: none;
      transition: all 0.15s ease;
    }
    .search-input:focus {
      background: var(--color-surface);
      border-color: var(--color-primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.12);
    }
    .search-shortcut {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 0.65rem;
      font-weight: 700;
      color: var(--color-text-muted);
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      pointer-events: none;
      font-family: 'JetBrains Mono', monospace;
    }

    .topbar-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .sync-controller {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      padding: 5px 12px;
      font-size: 0.74rem;
    }
    .sync-label {
      color: var(--color-text-muted);
      font-size: 0.7rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
      font-family: 'JetBrains Mono', monospace;
    }
    .sync-select {
      background: transparent;
      border: none;
      color: var(--color-primary);
      font-size: 0.74rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      outline: none;
      cursor: pointer;
    }
    .sync-select option { background: var(--color-surface); color: var(--color-text-main); }
    /* Theme Switch Toggle */
    .theme-switch {
      position: relative;
      width: 48px;
      height: 26px;
      border-radius: 9999px;
      background: #e2e8f0;
      border: 1px solid #cbd5e1;
      cursor: pointer;
      padding: 0;
      display: inline-flex;
      align-items: center;
      transition: background-color 0.25s ease, border-color 0.25s ease, box-shadow 0.2s ease;
      outline: none;
      box-sizing: border-box;
      user-select: none;
      flex-shrink: 0;
    }
    .theme-switch:hover {
      border-color: var(--color-primary-light);
    }
    .theme-switch:focus-visible {
      box-shadow: 0 0 0 2px var(--color-surface), 0 0 0 4px var(--color-primary);
    }
    .theme-switch-track-sun,
    .theme-switch-track-moon {
      position: absolute;
      top: 5px;
      width: 14px;
      height: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      pointer-events: none;
      transition: opacity 0.2s ease, color 0.2s ease;
    }
    .theme-switch-track-sun {
      left: 5px;
      color: #94a3b8;
    }
    .theme-switch-track-moon {
      right: 5px;
      color: #94a3b8;
    }
    .theme-switch-track-sun svg,
    .theme-switch-track-moon svg {
      width: 12px;
      height: 12px;
      stroke: currentColor;
    }
    .theme-switch-thumb {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #ffffff;
      border: 1px solid rgba(0, 0, 0, 0.08);
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15), 0 1px 2px rgba(0, 0, 0, 0.1);
      display: flex;
      align-items: center;
      justify-content: center;
      transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1), background-color 0.2s ease, border-color 0.2s ease;
      z-index: 2;
    }
    .thumb-icon {
      position: absolute;
      display: flex;
      align-items: center;
      justify-content: center;
      width: 12px;
      height: 12px;
      transition: opacity 0.2s ease, transform 0.2s ease;
    }
    .thumb-icon svg {
      width: 12px;
      height: 12px;
      stroke: currentColor;
    }
    .thumb-sun {
      color: #f59e0b;
      opacity: 1;
      transform: scale(1);
    }
    .thumb-moon {
      color: #818cf8;
      opacity: 0;
      transform: scale(0.6);
    }

    /* Dark Mode State for Switch */
    :root[data-theme="dark"] .theme-switch {
      background: #18181c;
      border-color: #2e2e36;
    }
    :root[data-theme="dark"] .theme-switch:hover {
      border-color: #3f3f46;
    }
    :root[data-theme="dark"] .theme-switch-track-sun {
      color: #71717a;
      opacity: 0.8;
    }
    :root[data-theme="dark"] .theme-switch-track-moon {
      color: #52525b;
      opacity: 0.4;
    }
    :root[data-theme="dark"] .theme-switch-thumb {
      transform: translateX(22px);
      background: #27272e;
      border-color: #383842;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.5);
    }
    :root[data-theme="dark"] .thumb-sun {
      opacity: 0;
      transform: scale(0.6);
    }
    :root[data-theme="dark"] .thumb-moon {
      opacity: 1;
      transform: scale(1);
    }
    .btn-icon {
      width: 34px;
      height: 34px;
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      color: var(--color-text-muted);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-icon:hover {
      color: var(--color-primary);
      border-color: var(--color-primary-light);
      background: var(--panel-hover);
    }
    .btn-icon svg { width: 15px; height: 15px; stroke: currentColor; }
    .btn-icon.spinning svg { animation: spin 0.8s linear infinite; }
    @keyframes spin { 100% { transform: rotate(360deg); } }

    /* Content Area */
    .content-container {
      padding: 28px 32px 76px;
      max-width: 1440px;
      width: 100%;
      margin: 0 auto;
      flex: 1;
    }

    /* Page Titles */
    .section-header {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .section-titles h2 {
      font-size: 1.65rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      color: var(--color-text-main);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-titles p {
      font-size: 0.82rem;
      color: var(--color-text-muted);
      margin-top: 4px;
    }
    .section-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Minimalist Flat Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 8px 16px;
      border-radius: var(--radius-md);
      font-size: 0.8rem;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
      text-decoration: none;
      outline: none;
      white-space: nowrap;
    }
    .btn svg { width: 15px; height: 15px; stroke: currentColor; flex-shrink: 0; }
    .btn-primary {
      background: var(--color-primary);
      color: #ffffff;
      font-weight: 600;
      border-color: var(--color-primary);
      box-shadow: 0 1px 2px rgba(99, 102, 241, 0.2);
    }
    .btn-primary:hover {
      background: var(--color-primary-light);
      border-color: var(--color-primary-light);
    }
    .btn-secondary {
      background: var(--panel-hover);
      border-color: var(--color-border-strong);
      color: var(--color-text-main);
    }
    .btn-secondary:hover {
      background: var(--color-border);
      border-color: var(--color-border-muted);
      color: var(--color-text-main);
    }
    .btn-outline {
      background: var(--color-surface);
      border-color: var(--color-border-strong);
      color: var(--color-text-main);
    }
    .btn-outline:hover {
      background: var(--panel-hover);
      border-color: var(--color-primary);
      color: var(--color-primary);
    }
    .btn-danger {
      background: var(--feedback-danger-bg);
      border-color: var(--feedback-danger-border);
      color: var(--feedback-danger-text);
      font-weight: 600;
    }
    .btn-danger:hover {
      background: var(--feedback-danger-border);
      border-color: var(--feedback-danger-text);
      color: var(--feedback-danger-text);
    }
    .btn-sm {
      padding: 5px 11px;
      font-size: 0.72rem;
      border-radius: var(--radius-sm);
    }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    /* Flat KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-top: 3px solid var(--card-accent, var(--color-primary)) !important;
      border-radius: var(--radius-md);
      padding: 18px 20px;
      position: relative;
      transition: all 0.15s ease;
      box-shadow: var(--shadow-sm);
    }
    .kpi-card:hover {
      box-shadow: var(--shadow-md);
      border-color: var(--color-border-strong);
    }
    .kpi-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .kpi-label {
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--color-text-muted);
      letter-spacing: 0.04em;
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
    }
    .kpi-icon {
      width: 32px;
      height: 32px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--color-primary-tint);
      border: 1px solid var(--color-accent-border);
      color: var(--card-accent, var(--color-primary));
    }
    .kpi-icon svg { width: 16px; height: 16px; stroke: currentColor; }
    .kpi-val {
      font-size: 2rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      line-height: 1.1;
      font-family: 'JetBrains Mono', monospace;
      color: var(--color-text-main);
    }
    .kpi-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px solid var(--color-border);
      font-size: 0.7rem;
    }
    .kpi-meta { color: var(--color-text-dim); }
    .kpi-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 7px;
      border-radius: var(--radius-sm);
      font-weight: 700;
      font-size: 0.65rem;
      font-family: 'JetBrains Mono', monospace;
    }
    .kpi-badge.positive {
      background: var(--feedback-success-bg);
      border: 1px solid #6ee7b7;
      color: var(--feedback-success-text);
    }
    .kpi-badge.alert {
      background: var(--feedback-warning-bg);
      border: 1px solid #fcd34d;
      color: var(--feedback-warning-text);
    }
    .kpi-badge.critical {
      background: var(--feedback-danger-bg);
      border: 1px solid #fca5a5;
      color: var(--feedback-danger-text);
    }

    /* Flat Tactical Panels */
    .tactical-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 18px;
      margin-bottom: 24px;
    }
    .panel {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      padding: 20px;
      position: relative;
      box-shadow: var(--shadow-sm);
    }
    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
      flex-wrap: wrap;
      gap: 12px;
    }
    .panel-title {
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--color-text-main);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .panel-sub { font-size: 0.72rem; color: var(--color-text-muted); margin-top: 2px; }

    /* Threat Chart Canvas */
    .chart-container {
      position: relative;
      height: 230px;
      width: 100%;
    }
    canvas#threatChart {
      width: 100% !important;
      height: 100% !important;
      display: block;
    }

    /* Flat Node Fleet Matrix */
    .node-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
      gap: 18px;
    }
    .node-card {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      padding: 18px;
      transition: all 0.15s ease;
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 12px;
      box-sizing: border-box;
      min-width: 0;
      box-shadow: var(--shadow-sm);
    }
    .node-card:hover {
      border-color: var(--color-border-strong);
      box-shadow: var(--shadow-md);
    }
    .node-card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-width: 0;
    }
    .node-ident {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
      flex: 1;
    }
    .node-avatar {
      width: 38px;
      height: 38px;
      border-radius: var(--radius-sm);
      background: var(--pill-bg);
      border: 1px solid var(--pill-border);
      color: var(--pill-text);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.78rem;
      font-family: 'JetBrains Mono', monospace;
      flex-shrink: 0;
    }
    .node-title-wrap {
      min-width: 0;
      flex: 1;
      overflow: hidden;
    }
    .node-title-wrap h3 {
      font-size: 0.92rem;
      font-weight: 700;
      color: var(--color-text-main);
      font-family: 'JetBrains Mono', monospace;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      line-height: 1.2;
    }
    .node-site-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      margin-top: 3px;
      font-size: 0.65rem;
      color: var(--color-text-muted);
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-sm);
      padding: 2px 7px;
      font-family: 'JetBrains Mono', monospace;
      cursor: pointer;
      transition: all 0.15s;
    }
    .node-site-pill:hover {
      border-color: var(--color-primary);
      color: var(--color-primary);
    }
    .node-site-pill svg {
      width: 11px;
      height: 11px;
      opacity: 0.7;
      flex-shrink: 0;
    }
    .node-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: var(--radius-sm);
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      flex-shrink: 0;
      line-height: 1;
      font-family: 'JetBrains Mono', monospace;
    }
    .node-badge.online {
      background: var(--feedback-success-bg);
      border: 1px solid var(--feedback-success-border);
      color: var(--feedback-success-text);
    }
    .node-badge.stale {
      background: var(--feedback-warning-bg);
      border: 1px solid var(--feedback-warning-border);
      color: var(--feedback-warning-text);
    }
    .node-details-list {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px 10px;
      padding: 10px 12px;
      background: var(--color-bg);
      border-radius: var(--radius-sm);
      border: 1px solid var(--color-border);
      min-width: 0;
    }
    .node-detail-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
    }
    .detail-k {
      font-size: 0.62rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--color-text-muted);
    }
    .detail-v {
      font-size: 0.72rem;
      color: var(--color-text-main);
      font-family: 'JetBrains Mono', monospace;
      word-break: break-all;
    }
    .node-caps {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
    }
    .cap-pill {
      font-size: 0.62rem;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: var(--radius-sm);
      background: var(--pill-bg);
      border: 1px solid var(--pill-border);
      color: var(--pill-text);
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
      transition: all 0.15s ease;
    }
    .cap-pill:hover {
      border-color: var(--color-primary-light);
      color: var(--color-text-main);
    }
    .node-actions {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: auto;
      padding-top: 14px;
      border-top: 1px solid var(--color-border);
      width: 100%;
      box-sizing: border-box;
    }
    .node-actions .btn {
      flex: 1 1 auto;
      justify-content: center;
      padding: 7px 10px;
      font-size: 0.72rem;
      white-space: nowrap;
      gap: 5px;
      min-width: 0;
    }
    .node-actions .btn svg {
      width: 13px;
      height: 13px;
      flex-shrink: 0;
    }
    .node-actions .btn-unenroll {
      flex: 0 0 34px;
      width: 34px;
      height: 32px;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: var(--radius-sm);
    }

    /* Activity Feed Table */
    .table-wrap {
      width: 100%;
      overflow-x: auto;
      border-radius: var(--radius-md);
    }
    table.data-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.8rem;
    }
    table.data-table th {
      background: var(--color-bg);
      color: var(--color-text-muted);
      font-weight: 700;
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 10px 14px;
      border-bottom: 1px solid var(--color-border-strong);
      font-family: 'JetBrains Mono', monospace;
    }
    table.data-table td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--color-border);
      color: var(--color-text-main);
      vertical-align: middle;
    }
    table.data-table tr:hover td {
      background: var(--panel-hover);
    }
    .event-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 7px;
      border-radius: var(--radius-sm);
      font-size: 0.68rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }
    .event-badge.session { background: var(--feedback-info-bg); color: var(--feedback-info-text); border: 1px solid var(--feedback-info-border); }
    .event-badge.flag { background: #ef4444 !important; color: #ffffff !important; border: 1px solid #dc2626 !important; font-weight: 700; box-shadow: 0 0 8px rgba(239, 68, 68, 0.4); }
    .event-badge.command { background: var(--feedback-warning-bg); color: var(--feedback-warning-text); border: 1px solid var(--feedback-warning-border); }
    .event-badge.canary { background: var(--pill-bg); color: var(--pill-text); border: 1px solid var(--pill-border); }
    .event-badge.generic { background: var(--panel-hover); color: var(--color-text-main); border: 1px solid var(--color-border); }

    /* Expandable JSON payload */
    .payload-toggle {
      background: var(--color-surface);
      border: 1px solid var(--color-border-strong);
      color: var(--color-primary);
      padding: 3px 8px;
      border-radius: var(--radius-sm);
      font-size: 0.7rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-family: 'JetBrains Mono', monospace;
      transition: all 0.15s;
    }
    .payload-toggle:hover { background: var(--color-primary-tint); border-color: var(--color-primary-light); }
    .payload-box {
      margin-top: 8px;
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-sm);
      padding: 10px 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.7rem;
      color: var(--color-text-main);
      max-height: 280px;
      overflow-y: auto;
      word-break: break-all;
    }
    .payload-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--color-border);
    }
    .payload-tag {
      font-size: 0.62rem;
      font-weight: 700;
      color: var(--color-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-family: 'JetBrains Mono', monospace;
    }
    .payload-copy-btn {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      color: var(--color-text-muted);
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      font-size: 0.65rem;
      font-family: inherit;
      cursor: pointer;
      transition: all 0.15s;
    }
    .payload-copy-btn:hover { color: var(--color-primary); border-color: var(--color-primary); }

    /* Filters Bar */
    .filter-bar-label {
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--color-text-muted);
      font-family: 'JetBrains Mono', monospace;
      margin-right: 6px;
    }
    .filter-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .filter-btn {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      color: var(--color-text-muted);
      padding: 5px 12px;
      border-radius: var(--radius-sm);
      font-size: 0.72rem;
      font-weight: 600;
      cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
      transition: all 0.15s;
    }
    .filter-btn:hover { color: var(--color-text-main); border-color: var(--color-border-strong); }
    .filter-btn.active {
      background: var(--color-primary);
      border-color: var(--color-primary);
      color: #ffffff;
      font-weight: 700;
    }

    /* Flat Modal Dialog */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.4);
      backdrop-filter: blur(2px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
      padding: 20px;
    }
    .modal-overlay.active, .modal-overlay.open {
      opacity: 1;
      pointer-events: auto;
    }
    .modal-card {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-lg);
      width: 100%;
      max-width: 500px;
      padding: 24px;
      transform: scale(0.98);
      transition: transform 0.2s ease;
    }
    .modal-overlay.active .modal-card, .modal-overlay.open .modal-card {
      transform: scale(1);
    }
    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
    }
    .modal-header h3 {
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--color-text-main);
    }
    .modal-close {
      background: transparent;
      border: none;
      color: var(--color-text-muted);
      cursor: pointer;
      padding: 4px;
    }
    .modal-close:hover { color: var(--color-text-main); }
    .modal-close svg { width: 18px; height: 18px; stroke: currentColor; }

    /* Form Fields */
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 5px;
      margin-bottom: 14px;
    }
    .form-group label {
      font-size: 0.7rem;
      font-weight: 700;
      color: var(--color-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-family: 'JetBrains Mono', monospace;
    }
    .form-group input, .form-group select {
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      color: var(--color-text-main);
      padding: 9px 12px;
      border-radius: var(--radius-sm);
      font-size: 0.82rem;
      font-family: inherit;
      outline: none;
      transition: border-color 0.15s;
    }
    .form-group input:focus, .form-group select:focus {
      border-color: var(--color-primary);
      background: var(--color-surface);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.12);
    }
    .form-row {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 12px;
    }
    @media (max-width: 520px) {
      .form-row { grid-template-columns: 1fr; }
    }
    .settings-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 18px;
    }
    @media (max-width: 960px) {
      .settings-grid { grid-template-columns: 1fr; }
    }
    .form-hint {
      font-size: 0.68rem;
      color: var(--color-text-muted);
      line-height: 1.4;
      margin-top: 3px;
    }
    .form-error {
      background: var(--feedback-danger-bg);
      border: 1px solid var(--feedback-danger-border);
      color: var(--feedback-danger-text);
      padding: 9px 12px;
      border-radius: var(--radius-sm);
      font-size: 0.74rem;
      margin-bottom: 14px;
      display: none;
    }

    /* Slide-over Drawer */
    .drawer-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.4);
      backdrop-filter: blur(2px);
      z-index: 90;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
    }
    .drawer-overlay.active { opacity: 1; pointer-events: auto; }
    .drawer {
      position: fixed;
      top: 0;
      right: 0;
      bottom: 0;
      width: 100%;
      max-width: 520px;
      background: var(--color-surface);
      border-left: 1px solid var(--color-border);
      box-shadow: var(--shadow-lg);
      z-index: 95;
      transform: translateX(100%);
      transition: transform 0.25s ease;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      padding: 24px;
    }
    .drawer.active { transform: translateX(0); }
    .drawer-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--color-border);
      margin-bottom: 20px;
    }

    /* Integration Card */
    .integration-card {
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .integration-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .integration-card-header h4 {
      font-size: 0.92rem;
      font-weight: 700;
      color: var(--color-text-main);
    }
    .integration-kind {
      font-size: 0.65rem;
      color: var(--color-text-muted);
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
    }
    .integration-url {
      font-size: 0.72rem;
      color: var(--color-text-muted);
      font-family: 'JetBrains Mono', monospace;
      word-break: break-all;
    }
    .integration-actions {
      display: flex;
      gap: 8px;
      margin-top: 4px;
    }
    .integration-meta {
      font-size: 0.68rem;
      color: var(--color-text-dim);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 7px;
      border-radius: var(--radius-sm);
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
    }
    .status-badge.enabled {
      background: var(--feedback-success-bg);
      border: 1px solid var(--feedback-success-border);
      color: var(--feedback-success-text);
    }
    .status-badge.disabled {
      background: var(--feedback-warning-bg);
      border: 1px solid var(--feedback-warning-border);
      color: var(--feedback-warning-text);
    }

    /* Empty States */
    .empty-box {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 10px;
      padding: 48px 20px;
      text-align: center;
      color: var(--color-text-dim);
    }
    .empty-icon {
      width: 44px;
      height: 44px;
      border-radius: var(--radius-sm);
      background: var(--color-primary-tint);
      border: 1px solid var(--color-accent-border);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--color-primary);
    }
    .empty-icon svg { width: 22px; height: 22px; stroke: currentColor; }
    .empty-title { font-size: 0.95rem; font-weight: 700; color: var(--color-text-main); }
    .empty-desc { font-size: 0.76rem; color: var(--color-text-muted); max-width: 360px; }

    /* Toast */
    .toast-center {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 200;
      display: flex;
      flex-direction: column;
      gap: 8px;
      pointer-events: none;
    }
    .toast {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-left: 3px solid var(--color-primary);
      padding: 12px 16px;
      border-radius: var(--radius-sm);
      box-shadow: var(--shadow-lg);
      color: var(--color-text-main);
      font-size: 0.78rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 260px;
      max-width: 360px;
      transform: translateY(10px);
      opacity: 0;
      transition: all 0.2s ease;
      pointer-events: auto;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.error { border-left-color: var(--feedback-danger-text); }
    .toast.success { border-left-color: var(--feedback-success-text); }

    .attention-banner {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 16px 18px;
      margin-bottom: 20px;
      background: var(--color-primary-tint);
      border: 1px solid var(--color-accent-border);
      border-radius: var(--radius-md);
    }
    .attention-banner[hidden],
    .attention-banner:empty {
      display: none !important;
      border: none !important;
      padding: 0 !important;
      margin: 0 !important;
    }
    .attention-banner p { font-size: 0.8rem; color: var(--color-text-muted); margin-top: 4px; max-width: 52ch; }
    .kpi-card.kpi-link { text-decoration: none; color: inherit; cursor: pointer; display: block; }
    .segmented {
      display: inline-flex;
      background: var(--color-bg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      padding: 3px;
      gap: 2px;
    }
    .segmented button {
      border: 0;
      background: transparent;
      color: var(--color-text-muted);
      font: inherit;
      font-size: 0.8rem;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
    }
    .segmented button[aria-pressed="true"] {
      background: var(--color-surface);
      color: var(--color-text-main);
      box-shadow: var(--shadow-sm);
    }
    .settings-subnav {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 18px;
    }
    .settings-subnav a {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--color-text-muted);
      text-decoration: none;
      padding: 6px 10px;
      border-radius: var(--radius-md);
      border: 1px solid transparent;
    }
    .settings-subnav a.active, .settings-subnav a:hover {
      color: var(--color-primary);
      background: var(--color-primary-tint);
      border-color: var(--color-accent-border);
    }
    .search-overlay {
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      right: 0;
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-lg);
      z-index: 80;
      max-height: 360px;
      overflow-y: auto;
      display: none;
    }
    .search-overlay.open { display: block; }
    .search-group-title {
      font-size: 0.64rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--color-text-muted);
      padding: 8px 12px 4px;
      font-family: 'JetBrains Mono', monospace;
    }
    .search-hit {
      display: block;
      width: 100%;
      text-align: left;
      border: 0;
      background: transparent;
      padding: 8px 12px;
      font: inherit;
      font-size: 0.8rem;
      color: var(--color-text-main);
      cursor: pointer;
    }
    .search-hit:hover, .search-hit[aria-selected="true"] { background: var(--panel-hover); }
    .search-box { position: relative; }
    .drawer-tabs {
      display: flex;
      gap: 4px;
      border-bottom: 1px solid var(--color-border);
      margin-bottom: 16px;
    }
    .drawer-tabs button {
      border: 0;
      background: transparent;
      padding: 8px 12px;
      font: inherit;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--color-text-muted);
      cursor: pointer;
      border-bottom: 2px solid transparent;
    }
    .drawer-tabs button[aria-selected="true"] {
      color: var(--color-primary);
      border-bottom-color: var(--color-primary);
    }
    .card-overflow { position: relative; }
    .overflow-menu {
      position: absolute;
      right: 0;
      top: 100%;
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-lg);
      min-width: 160px;
      z-index: 20;
      display: none;
    }
    .overflow-menu.open { display: block; }
    .overflow-menu button {
      display: block;
      width: 100%;
      text-align: left;
      border: 0;
      background: transparent;
      padding: 8px 12px;
      font: inherit;
      font-size: 0.78rem;
      cursor: pointer;
      color: var(--color-text-main);
    }
    .overflow-menu button:hover { background: var(--panel-hover); }
    .user-chip {
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--color-text-muted);
      padding: 4px 8px;
      border: 1px solid var(--color-border);
      border-radius: 999px;
    }
    .infra-line {
      font-size: 0.74rem;
      color: var(--color-text-muted);
      margin: 0 0 16px;
    }

    /* Responsive */
    @media (max-width: 1200px) {
      .kpi-grid { grid-template-columns: repeat(2, 1fr); }
      .tactical-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 859px) {
      .app-shell,
      :root.preload-sidebar-collapsed .app-shell,
      .app-shell.sidebar-collapsed {
        grid-template-columns: 1fr;
      }
      .sidebar,
      :root.preload-sidebar-collapsed .sidebar,
      .app-shell.sidebar-collapsed .sidebar {
        position: fixed;
        left: 0;
        top: 0;
        height: 100vh;
        width: var(--sidebar-w);
        padding: 20px 14px 18px;
        transform: translateX(-100%);
        visibility: visible;
        opacity: 1;
        pointer-events: auto;
        z-index: 120;
      }
      .app-shell.nav-open .sidebar {
        transform: translateX(0);
      }
      :root.preload-sidebar-collapsed .brand-info,
      :root.preload-sidebar-collapsed .nav-group-title,
      :root.preload-sidebar-collapsed .nav-item a span,
      :root.preload-sidebar-collapsed .nav-badge,
      :root.preload-sidebar-collapsed .sidebar-footer,
      .app-shell.sidebar-collapsed .brand-info,
      .app-shell.sidebar-collapsed .nav-group-title,
      .app-shell.sidebar-collapsed .nav-item a span,
      .app-shell.sidebar-collapsed .nav-badge,
      .app-shell.sidebar-collapsed .sidebar-footer {
        opacity: 1;
        transform: none;
        max-width: none;
        max-height: none;
        margin: revert;
        padding: revert;
        pointer-events: auto;
        visibility: visible;
        display: revert;
      }
      .app-footer,
      :root.preload-sidebar-collapsed .app-footer,
      .app-shell.sidebar-collapsed .app-footer {
        left: 0;
      }
      .nav-backdrop {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(15, 23, 42, 0.45);
        z-index: 110;
      }
      .app-shell.nav-open .nav-backdrop { display: block; }
      .content-container { padding: 20px 16px 84px; }
      .topbar { padding: 12px 16px; flex-wrap: wrap; }
      .kpi-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 580px) {
      .node-grid { grid-template-columns: 1fr; }
      .drawer { max-width: 100%; padding: 20px; }
      .topbar { flex-direction: column; align-items: stretch; gap: 12px; }
      .topbar-left { max-width: 100%; }
      .topbar-right { justify-content: space-between; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>
  <div class="app-shell">
    <div class="nav-backdrop" id="nav-backdrop"></div>
    <!-- Sidebar Navigation -->
    <aside class="sidebar" id="app-sidebar">
      <div class="sidebar-brand">
        <a class="brand-mark" href="/overview" data-tab="overview" aria-label="vAIvar">
          <img src="${VAIVAR_LOGO_URL}" alt="vAIvar Logo" width="64" height="64" />
        </a>
        <div class="brand-info">
          <h1>vAIvar</h1>
        </div>
      </div>

      <div class="nav-group-title">Command Center</div>
      <nav aria-label="Primary">
      <ul class="nav-list">
        <li class="nav-item">
          <a href="/overview" class="active" data-tab="overview" data-i18n-title="nav_overview" title="Overview">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>
            <span data-i18n="nav_overview">Overview</span>
          </a>
        </li>
        <li class="nav-item">
          <a href="/honeypots" data-tab="honeypots" data-i18n-title="nav_honeypots" title="Honeypots">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10z"/><circle cx="12" cy="11" r="3"/></svg>
            <span data-i18n="nav_honeypots">Honeypots</span>
            <span class="nav-badge" id="badge-node-count">0</span>
          </a>
        </li>
        <li class="nav-item">
          <a href="/activity" data-tab="activity" data-i18n-title="nav_activity" title="Activity">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            <span data-i18n="nav_activity">Activity</span>
            <span class="nav-badge alert" id="badge-events-count">0</span>
          </a>
        </li>
        <li class="nav-item">
          <a href="/settings" data-tab="settings" data-i18n-title="nav_settings" title="Settings">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06-.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            <span data-i18n="nav_settings">Settings</span>
          </a>
        </li>
      </ul>
      </nav>

      <div class="sidebar-footer">
        <div class="status-card">
          <div class="status-row">
            <span class="status-label">Central Node</span>
            <span class="status-val"><span class="pulse-dot"></span> Online</span>
          </div>
          <div class="status-row">
            <span class="status-label">Uptime</span>
            <span class="status-val mono" id="footer-uptime">0h 0m</span>
          </div>
          <div class="status-row">
            <span class="status-label">Storage DB</span>
            <span class="status-val mono" id="footer-storage">0 KB</span>
          </div>
        </div>
      </div>
    </aside>

    <!-- Main Workspace -->
    <div class="main-wrap">
      <!-- Top Control Bar -->
      <header class="topbar">
        <div class="topbar-left">
          <button class="btn-icon" id="btn-toggle-sidebar" title="Toggle Sidebar" aria-label="Toggle Sidebar" aria-expanded="true" aria-controls="app-sidebar">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 16px; height: 16px;"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/></svg>
          </button>
          <div class="search-box">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input class="search-input" id="global-search" type="text" placeholder="Search honeypots, sessions, events…" autocomplete="off" data-i18n-placeholder="search_placeholder" aria-autocomplete="list" aria-controls="search-overlay" aria-expanded="false">
            <div class="search-overlay" id="search-overlay" role="listbox" hidden></div>
            <span class="search-shortcut">/</span>
          </div>
        </div>

        <div class="topbar-right">
          <a class="threat-status-pill normal" id="threat-status-pill" title="Fleet Monitoring"><span class="pulse-dot"></span><span>MONITORING</span></a>
          <button class="btn-icon" id="btn-manual-refresh" title="Refresh Now" aria-label="Refresh Now">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/></svg>
          </button>
          <button class="theme-switch" id="btn-theme-toggle" role="switch" aria-checked="false" title="Switch to Dark Mode" aria-label="Toggle Light / Dark Mode">
            <span class="theme-switch-track-sun">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
            </span>
            <span class="theme-switch-track-moon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
            </span>
            <span class="theme-switch-thumb">
              <span class="thumb-icon thumb-sun">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
              </span>
              <span class="thumb-icon thumb-moon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              </span>
            </span>
          </button>
          <span class="user-chip" id="user-chip">Local</span>
        </div>
      </header>

      <!-- Main Workspace Views -->
      <main class="content-container" id="main">

        <!-- ================= OVERVIEW SECTION ================= -->
        <section id="view-overview" class="view-pane">
          <div class="section-header">
            <div class="section-titles">
              <h2 data-i18n="overview_title">Overview</h2>
              <p data-i18n="overview_subtitle">Fleet health, recent activity, and anything that needs you.</p>
            </div>
          </div>

          <div class="attention-banner" id="overview-attention" hidden></div>
          <p class="infra-line" id="overview-infra"></p>

          <!-- KPI Cards -->
          <div class="kpi-grid">
            <a class="kpi-card kpi-link" href="/honeypots" data-tab="honeypots" style="--card-accent: var(--cyan-glow)">
              <div class="kpi-top">
                <span class="kpi-label" data-i18n="kpi_honeypots">Honeypots</span>
                <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10z"/></svg></div>
              </div>
              <div class="kpi-val" id="stat-nodes">0</div>
              <div class="kpi-footer">
                <span class="kpi-meta" id="stat-nodes-meta">Enrolled</span>
                <span class="kpi-badge positive" id="stat-nodes-status">—</span>
              </div>
            </a>

            <a class="kpi-card kpi-link" href="/activity" data-tab="activity" style="--card-accent: var(--teal-soft)">
              <div class="kpi-top">
                <span class="kpi-label" data-i18n="kpi_events">Events</span>
                <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
              </div>
              <div class="kpi-val" id="stat-events">0</div>
              <div class="kpi-footer">
                <span class="kpi-meta">Latest captured</span>
                <span class="kpi-badge positive" id="stat-events-badge">—</span>
              </div>
            </a>

            <a class="kpi-card kpi-link" href="/activity?filter=flag" data-tab="activity" style="--card-accent: var(--red-soft)">
              <div class="kpi-top">
                <span class="kpi-label" data-i18n="kpi_flags">Flags</span>
                <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
              </div>
              <div class="kpi-val" id="stat-flags">0</div>
              <div class="kpi-footer">
                <span class="kpi-meta">Flags fired</span>
                <span class="kpi-badge alert" id="stat-flags-badge">None yet</span>
              </div>
            </a>

            <a class="kpi-card kpi-link" href="/activity?mode=sessions" data-tab="activity" style="--card-accent: var(--violet-soft)">
              <div class="kpi-top">
                <span class="kpi-label" data-i18n="kpi_sessions">Sessions</span>
                <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-4-4h-1"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
              </div>
              <div class="kpi-val" id="stat-sessions">0</div>
              <div class="kpi-footer">
                <span class="kpi-meta">Observed sessions</span>
                <span class="kpi-badge positive" id="stat-sessions-badge">—</span>
              </div>
            </a>
          </div>

          <!-- Chart and recent events -->
          <div class="tactical-grid">
            <div class="panel">
              <div class="panel-header">
                <div>
                  <h3 class="panel-title"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> <span data-i18n="panel_activity">Activity</span></h3>
                  <p class="panel-sub">Event volume in the last 12 minutes</p>
                </div>
                <div class="sync-label" id="chart-sync-label"></div>
              </div>
              <div class="chart-container">
                <canvas id="threatChart"></canvas>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header">
                <div>
                  <h3 class="panel-title"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> <span data-i18n="panel_stream">Recent events</span></h3>
                  <p class="panel-sub">Latest from enrolled honeypots</p>
                </div>
                <a class="btn btn-outline btn-sm" id="link-view-all-activity" data-i18n="link_view_all">View all</a>
              </div>
              <div id="overview-activity-list" style="display: flex; flex-direction: column; gap: 8px;">
                <div class="empty-box" style="padding: 24px 0;"><div class="empty-title" data-i18n="empty_events_title">No events yet</div><div class="empty-desc" data-i18n="empty_events_body">They appear here after a honeypot syncs.</div></div>
              </div>
            </div>
          </div>

          <!-- Honeypot Fleet Quick Map -->
          <div class="panel">
            <div class="panel-header">
              <div>
                <h3 class="panel-title"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10z"/></svg> <span data-i18n="panel_fleet">Honeypots</span></h3>
                <p class="panel-sub">Enrolled sensors and last contact</p>
              </div>
              <button class="btn btn-secondary btn-sm" id="link-enroll-hero">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> <span data-i18n="btn_add_honeypot">Add honeypot</span>
              </button>
            </div>
            <div class="node-grid" id="overview-nodes-grid">
              <div class="empty-box">
                <div class="empty-title" data-i18n="empty_fleet_title">Add your first honeypot</div>
                <div class="empty-desc" data-i18n="empty_fleet_body">This Central has no enrolled honeypots yet.</div>
                <div class="empty-desc" data-i18n="empty_fleet_helper">SSH into the VPS that will host the honeypot, run scripts/deploy.sh there, then add it here with host, control port, encrypted channel, and barrier token.</div>
              </div>
            </div>
          </div>
        </section>

        <!-- ================= HONEYPOTS SECTION ================= -->
        <section id="view-honeypots" class="view-pane" style="display: none;">
          <div class="section-header">
            <div class="section-titles">
              <h2 data-i18n="honeypots_title">Honeypots</h2>
              <p>Enroll, inspect, and manage honeypots from this Central.</p>
            </div>
            <div class="section-actions">
              <button class="btn btn-primary" id="btn-enroll-page">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span data-i18n="btn_enroll">Add honeypot</span>
              </button>
            </div>
          </div>

          <div class="filter-bar" role="group" aria-label="Connection">
            <span class="filter-bar-label" data-i18n="filter_connection">Connection</span>
            <button class="filter-btn active" data-conn-filter="all" data-i18n="filter_all">All</button>
            <button class="filter-btn" data-conn-filter="connected" data-i18n="status_connected">Connected</button>
            <button class="filter-btn" data-conn-filter="delayed" data-i18n="status_delayed">Delayed</button>
            <button class="filter-btn" data-conn-filter="waiting" data-i18n="status_waiting">Waiting for first sync</button>
          </div>
          <div class="filter-bar" role="group" aria-label="Control channel">
            <span class="filter-bar-label" data-i18n="filter_protocol">Control channel</span>
            <button class="filter-btn active" data-proto-filter="all" data-i18n="filter_all">All</button>
            <button class="filter-btn" data-proto-filter="encrypted" data-i18n="filter_encrypted">Encrypted</button>
            <button class="filter-btn" data-proto-filter="legacy" data-i18n="filter_legacy">Legacy</button>
          </div>

          <div class="node-grid" id="full-nodes-grid">
            <div class="empty-box">
              <div class="empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10z"/></svg></div>
              <div class="empty-title" data-i18n="empty_fleet_title">Add your first honeypot</div>
              <div class="empty-desc" data-i18n="empty_fleet_body">This Central has no enrolled honeypots yet.</div>
                <div class="empty-desc" data-i18n="empty_fleet_helper">SSH into the VPS that will host the honeypot, run scripts/deploy.sh there, then add it here with host, control port, encrypted channel, and barrier token.</div>
            </div>
          </div>
        </section>

        <!-- ================= ACTIVITY ================= -->
        <section id="view-activity" class="view-pane" style="display: none;">
          <div class="section-header">
            <div class="section-titles">
              <h2 data-i18n="activity_title">Activity</h2>
              <p data-i18n="activity_subtitle">Events and sessions from your honeypots.</p>
            </div>
            <div class="section-actions">
              <div class="segmented" role="tablist" aria-label="Activity mode">
                <button type="button" id="mode-events" aria-pressed="true" data-i18n="activity_mode_events">Events</button>
                <button type="button" id="mode-sessions" aria-pressed="false" data-i18n="activity_mode_sessions">Sessions</button>
              </div>
              <button class="btn btn-secondary btn-sm" id="btn-export-events">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                <span data-i18n="btn_export_events">Export JSON</span>
              </button>
            </div>
          </div>

          <div id="activity-events-pane">
          <div class="filter-bar" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 6px;">
              <button class="filter-btn active" data-event-filter="all" data-i18n="filter_events_all">All events</button>
              <button class="filter-btn" data-event-filter="attacks">🚨 Attacks</button>
              <button class="filter-btn" data-event-filter="flag" data-i18n="filter_events_flag">Flags</button>
              <button class="filter-btn" data-event-filter="session" data-i18n="filter_events_session">Sessions</button>
              <button class="filter-btn" data-event-filter="command" data-i18n="filter_events_command">Commands</button>
            </div>
            <div id="activity-active-filter-indicator" class="active-filter-indicator" style="display: none;">
              <span id="activity-active-filter-text">Filtered</span>
              <button type="button" class="btn-clear-filter" id="btn-clear-activity-filter" title="Clear filter">✕ Remove filter</button>
            </div>
          </div>

          <div class="panel" style="padding: 0; overflow: hidden;">
            <div class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event Classification</th>
                    <th>Session ID</th>
                    <th>Payload & Details</th>
                    <th style="text-align: right;">Action</th>
                  </tr>
                </thead>
                <tbody id="activity-table-body">
                  <tr><td colspan="5"><div class="empty-box"><div class="empty-title" data-i18n="empty_events_title">No events yet</div></div></td></tr>
                </tbody>
              </table>
            </div>
          </div>
          </div>

          <div id="activity-sessions-pane" style="display: none;">
            <div style="overflow-x: auto;">
              <table class="data-table" id="sessions-table">
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>Honeypot</th>
                    <th>Agent Class</th>
                    <th>Confidence</th>
                    <th>Events</th>
                    <th>Last Seen</th>
                    <th>Tooling</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody id="sessions-grid"></tbody>
              </table>
            </div>
          </div>
        </section>

        <section id="view-sessions" class="view-pane" style="display: none;" hidden></section>

        <!-- ================= SETTINGS SECTION ================= -->
        <section id="view-settings" class="view-pane" style="display: none;">
          <div class="section-header">
            <div class="section-titles">
              <h2 data-i18n="settings_title">Settings</h2>
              <p>Integrations, access, infrastructure, and this browser.</p>
            </div>
          </div>

          <nav class="settings-subnav" aria-label="Settings sections">
            <a href="/settings?section=integrations" data-settings-section="integrations" class="active" data-i18n="settings_section_integrations">Integrations</a>
            <a href="/settings?section=users" data-settings-section="users" data-i18n="settings_section_users">Users & permissions</a>
            <a href="/settings?section=infrastructure" data-settings-section="infrastructure" data-i18n="settings_section_infrastructure">Infrastructure</a>
            <a href="/settings?section=general" data-settings-section="general" data-i18n="settings_section_general">General</a>
          </nav>

          <div class="settings-grid">
            <div class="panel" id="settings-users">
              <div class="panel-header">
                <div><h3 class="panel-title" data-i18n="settings_auth">Users &amp; permissions</h3><p class="panel-sub">Roles come from Keycloak group membership. Central never stores users or passwords.</p></div>
              </div>
              <div id="accounts-list" style="display:flex;flex-direction:column;gap:14px;">
                <p class="panel-sub">Human identities live in <strong>Keycloak</strong> (realm <code>vaivar</code>, client <code>vaivar-central</code>). To change what someone can do, move them between these groups in Keycloak — the highest group wins:</p>
                <ul style="margin:6px 0 0 18px;line-height:1.7">
                  <li><code>vaivar-viewer</code> — read only (dashboard, events, nodes).</li>
                  <li><code>vaivar-user</code> — fleet hand: add, delete, restart, rotate.</li>
                  <li><code>vaivar-admin</code> — also integrations &amp; settings.</li>
                  <li><code>vaivar-superadmin</code> — break-glass + plane secrets (not "admin + one tick").</li>
                </ul>
                <p class="panel-sub" style="margin-top:8px" id="accounts-message">Machines (Edge ingest, metrics) keep their own static tokens and are not Keycloak users.</p>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header">
                <div><h3 class="panel-title" data-i18n="settings_retention">Storage & Retention</h3><p class="panel-sub">Database pruning and event archival policy</p></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 14px;">
                <div class="form-group">
                  <label for="input-retention" data-i18n="settings_retention">Data Retention (Days)</label>
                  <input type="number" id="input-retention" value="90" min="1" max="365" disabled>
                  <span class="form-hint" data-i18n="settings_retention_stub">Retention is not persisted yet.</span>
                </div>
                <div style="margin-top: 10px;">
                  <button class="btn btn-primary" id="btn-save-settings" disabled>
                    <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    <span data-i18n="btn_save_settings">Save Retention Policy</span>
                  </button>
                </div>
                <div style="margin-top: 20px; padding-top: 18px; border-top: 1px solid var(--color-border);">
                  <label style="font-size: 0.74rem; font-weight: 700; color: var(--text-soft); text-transform: uppercase;">Session Management</label>
                  <div style="margin-top: 8px;">
                    <button class="btn btn-danger btn-sm" id="btn-logout">
                      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                      Terminate Session / Logout
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header">
                <div><h3 class="panel-title" data-i18n="lang_selector">Language</h3><p class="panel-sub" data-i18n="lang_sub">Select interface language. Uses bundled locale files from the server.</p></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 14px;">
                <select id="setting-language" class="sync-select" style="max-width: 280px;">
                  ${AVAILABLE_LOCALES.map((loc) => {
                    const label = loc === 'eng' ? 'English (eng)' : loc === 'esp' ? 'Español (esp)' : loc.toUpperCase();
                    return `<option value="${escapeServerHtml(loc)}">${escapeServerHtml(label)}</option>`;
                  }).join('')}
                </select>
                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                  <button class="btn btn-secondary" id="btn-apply-language" type="button" title="Preview language without saving">
                    <svg viewBox="0 0 24 24" fill="none" stroke-width="2" style="width: 15px; height: 15px;"><path d="M5 12l5 5L20 7"/></svg>
                    <span data-i18n="btn_apply_language">Apply</span>
                  </button>
                  <button class="btn btn-primary" id="btn-save-language" type="button" title="Save language preference permanently">
                    <svg viewBox="0 0 24 24" fill="none" stroke-width="2" style="width: 15px; height: 15px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    <span data-i18n="btn_save_language">Save Language</span>
                  </button>
                  <button class="btn btn-secondary" id="btn-revert-language" type="button" style="display: none;" title="Revert to saved language">
                    <svg viewBox="0 0 24 24" fill="none" stroke-width="2" style="width: 15px; height: 15px;"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                    <span data-i18n="btn_revert_language">Revert</span>
                  </button>
                </div>
                <span class="form-hint" id="language-status-hint" style="margin: 0;" data-i18n="hint_language_workflow">Select a language, click Apply to preview, and Save to keep permanently.</span>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header">
                <div><h3 class="panel-title" data-i18n="settings_sync">Telemetry Synchronization</h3><p class="panel-sub">Automated polling interval for fleet telemetry and events</p></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 14px;">
                <div class="form-group">
                  <label for="sync-rate" data-i18n="settings_sync_interval">Polling Interval</label>
                  <select id="sync-rate" class="sync-select" style="max-width: 280px;">
                    <option value="5000">Every 5s</option>
                    <option value="15000" selected>Every 15s (Default)</option>
                    <option value="30000">Every 30s</option>
                    <option value="0">Manual only</option>
                  </select>
                  <span class="form-hint" data-i18n="settings_sync_help">How often this browser refreshes. Does not change the server poller (30s) and is stored only in this browser.</span>
                </div>
              </div>
            </div>

            <!-- ================= INTEGRATIONS PANEL ================= -->
            <div class="panel" id="settings-infrastructure" style="grid-column: 1 / -1;">
              <div class="panel-header">
                <div><h3 class="panel-title" data-i18n="settings_section_infrastructure">Infrastructure</h3><p class="panel-sub" data-i18n="infra_unavailable">Infrastructure telemetry is not available</p></div>
              </div>
              <p class="infra-line" id="settings-infra-line"></p>
            </div>

            <div class="panel" id="settings-integrations" style="grid-column: 1 / -1;">
              <div class="panel-header">
                <div><h3 class="panel-title" data-i18n="settings_integrations">Integrations</h3><p class="panel-sub">OpenCTI, Splunk, Prometheus/Grafana destinations. Configuration is persisted and never stored in cleartext credentials.</p></div>
              </div>
              <div id="integrations-list" style="display: flex; flex-direction: column; gap: 12px;"></div>
              <div style="margin-top: 14px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <button class="btn btn-primary btn-sm" id="btn-add-integration" type="button">
                  <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
                  <span data-i18n="btn_add_integration">Add Integration</span>
                </button>
                <span style="font-size: 0.74rem; color: var(--text-soft);">Prometheus: scrape your central endpoint for /metrics. Grafana: add /metrics as a Prometheus datasource.</span>
              </div>
            </div>
          </div>
        </section>

      </main>

      <!-- App Footer - Centralized Platform Version -->
      <footer class="app-footer">
        <div class="footer-col-left">
          <div class="footer-badge-group">
            <span class="footer-brand" data-i18n="footer_central">vAIvar Central</span>
          </div>
          <span class="footer-meta" id="footer-updated">—</span>
          <span class="footer-credit">this application is created by <a href="https://github.com/yz9yt" target="_blank" rel="noopener noreferrer" style="color:inherit;text-decoration:underline">@yz9yt</a></span>
        </div>
        <div class="footer-col-right">
          <div class="footer-metric">
            <span class="footer-metric-lbl">VERSION</span>
            <span class="footer-metric-val mono">v${safeVersion}</span>
          </div>
          <div class="footer-sep"></div>
          <div class="footer-metric">
            <span class="footer-metric-lbl">SPEC</span>
            <span class="footer-metric-val mono">vaivar.event.v2</span>
          </div>
          <div class="footer-metric" style="display:none">
            <span class="footer-metric-val">${safeCodename}</span>
          </div>
        </div>
      </footer>
    </div>
  </div>

  <!-- ================= ENROLL NODE MODAL ================= -->
  <div class="modal-overlay" id="modal-enroll">
    <div class="modal-card">
      <div class="modal-header">
        <h3 id="modal-enroll-title" data-i18n="modal_enroll_title">Add honeypot</h3>
        <button class="modal-close" id="btn-close-enroll" aria-label="Close"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </div>
      <p style="font-size: 0.78rem; color: var(--text-soft); margin-bottom: 18px;" data-i18n="modal_enroll_hint">Central connects out to the client. The client does not need this address.</p>

      <div class="form-error" id="enroll-error"></div>
      <div id="enroll-step-1">
      <div class="panel" style="margin-bottom:16px; padding:14px;">
        <div class="panel-title" style="font-size:0.82rem;" data-i18n="bootstrap_title">Central-approved deployment</div>
        <p class="panel-sub" style="margin:5px 0 12px;" data-i18n="bootstrap_hint">Generate a one-time command for a host with no Internet. It downloads the approved image from this Central and registers the node automatically.</p>
        <div class="form-row">
          <div class="form-group">
            <label for="enroll-public-port" data-i18n="label_exposed_port">Exposed honeypot port</label>
          <input id="enroll-public-port" type="number" value="" placeholder="Port selected during deploy" min="1" max="65535">
          </div>
          <div class="form-group">
            <label for="enroll-profile" data-i18n="label_simulates">Simulates</label>
            <select id="enroll-profile">
              <option value="all" data-i18n="profile_all">All surfaces</option>
              <option value="http" data-i18n="profile_http">HTTP API</option>
              <option value="wiki" data-i18n="profile_wiki">Wiki</option>
              <option value="openapi" data-i18n="profile_openapi">OpenAPI</option>
              <option value="mcp" data-i18n="profile_mcp">MCP</option>
            </select>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label for="enroll-install-dir" data-i18n="label_install_dir">Install directory</label>
            <input id="enroll-install-dir" type="text" value="/opt/vaivar" spellcheck="false">
          </div>
          <div class="form-group">
            <label for="enroll-project-name" data-i18n="label_compose_project">Compose project</label>
          <input id="enroll-project-name" type="text" value="" placeholder="Unique Compose project" pattern="[a-z0-9][a-z0-9_-]{0,62}" spellcheck="false">
          </div>
        </div>
        <div class="form-group">
          <label for="enroll-site-id" data-i18n="label_site_id">Honeypot site ID</label>
          <input id="enroll-site-id" type="text" value="" placeholder="Stable site ID" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" spellcheck="false">
        </div>
        <p class="panel-sub" style="margin:0 0 12px;" data-i18n="help_multi_instance">Use a different directory and project when several honeypots share one host.</p>
        <button class="btn btn-secondary btn-sm" type="button" id="btn-prepare-bootstrap" data-i18n="btn_prepare_deploy">Generate deploy command</button>
        <div id="bootstrap-command-wrap" hidden style="margin-top:12px;">
          <textarea id="bootstrap-command" readonly rows="5" style="width:100%; box-sizing:border-box; font-family:monospace; font-size:0.7rem; resize:vertical;"></textarea>
          <button class="btn btn-outline btn-sm" type="button" id="btn-copy-bootstrap" style="margin-top:8px;" data-i18n="btn_copy_command">Copy command</button>
          <p class="panel-sub" style="margin-top:8px;" data-i18n="bootstrap_token_warning">This command contains a one-time bootstrap token. Keep it private and use it before it expires.</p>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label for="enroll-host" data-i18n="label_host">Host / IP Address</label>
          <input id="enroll-host" type="text" placeholder="honeypot.example or IP" value="">
          <span class="form-hint" data-i18n="help_separate_host">Must be the honeypot host, not this Central.</span>
        </div>
        <div class="form-group">
          <label for="enroll-port" data-i18n="label_port">Control API port</label>
          <input id="enroll-port" type="number" value="" placeholder="Control port selected during deploy" min="1" max="65535">
        </div>
      </div>

      <div class="form-group">
        <label for="enroll-channel" data-i18n="label_control_channel">Control channel</label>
        <select id="enroll-channel">
          <option value="encrypted">Application-encrypted RPC (HTTP)</option>
          <option value="legacy">Legacy HTTP (unencrypted)</option>
        </select>
      </div>

      <div class="form-group">
        <label for="enroll-token" data-i18n="label_token">Barrier token</label>
        <div style="position: relative;">
          <input id="enroll-token" type="password" placeholder="At least 16 characters token" style="padding-right: 40px; width: 100%;">
          <button type="button" id="btn-toggle-token-vis" aria-label="Show barrier token" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: transparent; border: none; color: var(--text-dim); cursor: pointer;">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
        <span class="form-hint" data-i18n="hint_token">The barrier token authenticates the node with mutual cryptographic verification.</span>
      </div>
      </div>
      <div id="enroll-step-2" hidden>
        <div id="enroll-preview-summary" class="empty-box" style="padding: 12px 0;"></div>
      </div>

      <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 24px;">
        <button class="btn btn-secondary" id="btn-cancel-enroll" data-i18n="btn_cancel">Cancel</button>
        <button class="btn btn-secondary" id="btn-enroll-back" hidden data-i18n="btn_back">Back</button>
        <button class="btn btn-primary" id="btn-test-connection">
          <span data-i18n="btn_test_connection">Test connection</span>
        </button>
        <button class="btn btn-primary" id="btn-submit-enroll" hidden>
          <span data-i18n="btn_add_honeypot">Add honeypot</span>
        </button>
      </div>
    </div>
  </div>

  <!-- ================= INTEGRATION MODAL ================= -->
  <div class="modal-overlay" id="integration-modal">
    <div class="modal-card">
      <div class="modal-header">
        <h3 id="integration-modal-title">Add Integration</h3>
        <button class="modal-close" id="integration-close" type="button"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </div>
      <div id="integration-help" style="font-size: 0.78rem; color: var(--text-soft); margin-bottom: 18px;"></div>
      <div class="form-error" id="integration-status" style="display: none; margin-bottom: 14px;"></div>

      <div class="form-row">
        <div class="form-group">
          <label for="integration-kind">Kind</label>
          <select id="integration-kind">
            <option value="cti">OpenCTI (STIX 2.1)</option>
            <option value="siem">Splunk HEC</option>
            <option value="metrics">Prometheus</option>
            <option value="dashboard">Grafana</option>
          </select>
        </div>
        <div class="form-group">
          <label for="integration-name">Identifier Name</label>
          <input id="integration-name" type="text" placeholder="e.g. opencti-prod">
        </div>
      </div>
      <div class="form-group">
        <label for="integration-url">Endpoint URL</label>
        <input id="integration-url" type="text" placeholder="https://opencti.example.com">
      </div>
      <div class="form-group">
        <label for="integration-token">Auth / Bearer Token</label>
        <input id="integration-token" type="password" placeholder="API token / HEC token">
      </div>
      <div class="form-row" id="integration-extra-row">
        <div class="form-group">
          <label for="integration-index">Index (optional)</label>
          <input id="integration-index" type="text" placeholder="vaivar">
        </div>
        <div class="form-group">
          <label for="integration-source">Source (optional)</label>
          <input id="integration-source" type="text" placeholder="vaivar-central">
        </div>
        <div class="form-group">
          <label for="integration-sourcetype">Sourcetype (optional)</label>
          <input id="integration-sourcetype" type="text" placeholder="vaivar:events">
        </div>
      </div>

      <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 24px;">
        <button class="btn btn-secondary" id="integration-cancel" type="button">Cancel</button>
        <button class="btn btn-primary" id="integration-save" type="button">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          Save Integration
        </button>
      </div>
    </div>
  </div>

  <!-- ================= NODE DETAIL DRAWER ================= -->
  <div class="drawer-overlay" id="drawer-overlay"></div>
  <div class="drawer" id="node-drawer">
    <div class="drawer-head">
      <div style="min-width: 0; flex: 1; margin-right: 12px;">
        <h3 style="font-size: 1.25rem; font-weight: 800; color: var(--color-text-main); word-break: break-word;" id="drawer-node-title">Node Inspection</h3>
        <p style="font-size: 0.76rem; color: var(--text-dim); word-break: break-all;" id="drawer-node-site">Site ID: —</p>
      </div>
      <button class="modal-close" id="btn-close-drawer"><svg viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>

    <div style="display: flex; flex-direction: column; gap: 20px;" id="drawer-content">
      <!-- Injected by JavaScript -->
    </div>
  </div>

  <!-- Toast Center -->
  <div class="toast-center" id="toast-center" aria-live="polite" aria-relevant="additions"></div>

  <!-- Application Logic -->
  <script>
    (function() {
      const api = '/api/v1';

      // === i18n (translation dictionary injected from langs/*.txt) ===
      const __loc = (function() {
        const _ts = ${JSON.stringify(TRANSLATIONS)};
        const AVAILABLE = ${JSON.stringify(AVAILABLE_LOCALES)};
        const FALLBACK_LOCALE = '${FALLBACK_LOCALE}';
        let locale = localStorage.getItem('vaivar-locale') || FALLBACK_LOCALE;
        if (AVAILABLE.indexOf(locale) === -1) locale = FALLBACK_LOCALE;
        const t = function(key) {
          const set = _ts[locale] || _ts[FALLBACK_LOCALE] || {};
          return set[key] || (_ts[FALLBACK_LOCALE] || {})[key] || key;
        };
        const applyTranslations = function() {
          document.documentElement.lang = locale === 'esp' ? 'es' : 'en';
          const search = document.getElementById('global-search');
          if (search) {
            const sp = t('search_placeholder') || t('placeholder_search');
            if (sp) {
              search.placeholder = sp;
              search.title = sp;
            }
          }
          const sl = document.getElementById('setting-language');
          if (sl) sl.value = locale;
          document.querySelectorAll('[data-i18n]').forEach(el => {
            const k = el.getAttribute('data-i18n');
            const val = t(k);
            if (val && val !== k) el.textContent = val;
          });
          document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const k = el.getAttribute('data-i18n-title');
            const val = t(k);
            if (val && val !== k) el.setAttribute('title', val);
          });
          document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const k = el.getAttribute('data-i18n-placeholder');
            const val = t(k);
            if (val && val !== k) el.setAttribute('placeholder', val);
          });
        };
        const setLocale = function(newLoc, persist) {
          if (AVAILABLE.indexOf(newLoc) !== -1) {
            locale = newLoc;
            if (persist) {
              try { localStorage.setItem('vaivar-locale', newLoc); } catch (e) {}
            }
            applyTranslations();
          }
        };
        const saveLocale = function(newLoc) {
          setLocale(newLoc, true);
        };
        return { t: t, applyTranslations: applyTranslations, setLocale: setLocale, saveLocale: saveLocale, getLocale: () => locale };
      })();

      // State
      const NODE_STALE_MS = 90_000;
      let state = {
        stats: { nodes: 0, events: 0, flags: 0, sessions: 0, size_bytes: 0, uptime_seconds: 0, version: '' },
        nodes: [],
        templates: [],
        events: [],
        activityRows: [],
        activeTab: 'overview',
        activityMode: 'events',
        syncInterval: 15000,
        syncTimer: null,
        connFilter: 'all',
        protoFilter: 'all',
        eventFilter: 'all',
        searchQuery: '',
        lastRefresh: 0,
        me: { role: null, dev_mode: true },
        mePermissions: [],
        enrollPreview: null,
        settingsSection: 'integrations',
      };

      // Elements
      const els = {
        statNodes: document.getElementById('stat-nodes'),
        statEvents: document.getElementById('stat-events'),
        statFlags: document.getElementById('stat-flags'),
        statSessions: document.getElementById('stat-sessions'),
        statFlagsBadge: document.getElementById('stat-flags-badge'),
        badgeNodeCount: document.getElementById('badge-node-count'),
        badgeEventsCount: document.getElementById('badge-events-count'),
        statNodesStatus: document.getElementById('stat-nodes-status'),
        footerUptime: document.getElementById('footer-uptime'),
        footerStorage: document.getElementById('footer-storage'),
        overviewNodesGrid: document.getElementById('overview-nodes-grid'),
        overviewActivityList: document.getElementById('overview-activity-list'),
        fullNodesGrid: document.getElementById('full-nodes-grid'),
        activityTableBody: document.getElementById('activity-table-body'),
        sessionsGrid: document.getElementById('sessions-grid'),
        globalSearch: document.getElementById('global-search'),
        syncRate: document.getElementById('sync-rate'),
        btnManualRefresh: document.getElementById('btn-manual-refresh'),
        modalEnroll: document.getElementById('modal-enroll'),
        integrationModal: document.getElementById('integration-modal'),
        drawerOverlay: document.getElementById('drawer-overlay'),
        nodeDrawer: document.getElementById('node-drawer'),
        drawerContent: document.getElementById('drawer-content'),
        drawerNodeTitle: document.getElementById('drawer-node-title'),
        drawerNodeSite: document.getElementById('drawer-node-site'),
        toastCenter: document.getElementById('toast-center'),
        threatChartCanvas: document.getElementById('threatChart'),
      };

      // Toast System
      const showToast = (message, type = 'info') => {
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        const iconSvg = type === 'error'
          ? '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
          : (type === 'success'
            ? '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>'
            : '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>');
        toast.innerHTML = iconSvg + '<span>' + escapeHtml(message) + '</span>';
        els.toastCenter.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 10);
        setTimeout(() => {
          toast.classList.remove('show');
          setTimeout(() => toast.remove(), 300);
        }, 3500);
      };

      // Helpers
      function escapeHtml(val) {
        return String(val ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
      }

      function formatNumber(val) {
        return Number(val ?? 0).toLocaleString();
      }

      function formatBytes(bytes) {
        const b = Number(bytes || 0);
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(1) + ' MB';
      }

      function formatUptime(seconds) {
        const s = Math.floor(seconds || 0);
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        return h + 'h ' + m + 'm';
      }

      function formatDate(ts) {
        if (!ts) return 'Never';
        const d = new Date(ts);
        if (Number.isNaN(d.getTime())) return '—';
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' · ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
      }

      function timeAgo(ms) {
        if (!ms) return 'Unknown';
        const diff = Date.now() - Number(ms);
        if (diff < 5000) return 'Just now';
        const sec = Math.floor(diff / 1000);
        if (sec < 60) return sec + 's ago';
        const min = Math.floor(sec / 60);
        if (min < 60) return min + 'm ago';
        const hrs = Math.floor(min / 60);
        if (hrs < 24) return hrs + 'h ago';
        return Math.floor(hrs / 24) + 'd ago';
      }

      // API Client
      async function apiFetch(path, options = {}) {
        try {
          const res = await fetch(api + path, { credentials: 'same-origin', ...options });
          const text = await res.text();
          let body = null;
          try { body = text ? JSON.parse(text) : null; } catch {}
          return { ok: res.ok, status: res.status, body };
        } catch (err) {
          return { ok: false, status: 0, body: { error: err.message } };
        }
      }

      // Copy to Clipboard
      window.copyToClipboard = function(text, label = 'Copied') {
        navigator.clipboard.writeText(text).then(() => {
          showToast(label + ' to clipboard!', 'success');
        }).catch(() => {
          showToast('Could not copy text', 'error');
        });
      };

      const routes = {
        overview: { path: '/overview', title: 'Overview | vAIvar Central' },
        honeypots: { path: '/honeypots', title: 'Honeypots | vAIvar Central' },
        activity: { path: '/activity', title: 'Activity | vAIvar Central' },
        settings: { path: '/settings', title: 'Settings | vAIvar Central' },
      };

      function serializeQuery() {
        const p = new URLSearchParams();
        if (state.activeTab === 'activity' && state.activityMode === 'sessions') p.set('mode', 'sessions');
        if (state.activeTab === 'activity' && state.eventFilter && state.eventFilter !== 'all') p.set('filter', state.eventFilter);
        if (state.activeTab === 'honeypots') {
          if (state.connFilter !== 'all') p.set('conn', state.connFilter);
          if (state.protoFilter !== 'all') p.set('proto', state.protoFilter);
        }
        if (state.activeTab === 'settings' && state.settingsSection && state.settingsSection !== 'integrations') p.set('section', state.settingsSection);
        if (state.searchQuery && (state.activeTab === 'honeypots' || state.activeTab === 'activity')) p.set('search', state.searchQuery);
        const qs = p.toString();
        return qs ? '?' + qs : '';
      }

      function applyActivityMode() {
        const eventsPane = document.getElementById('activity-events-pane');
        const sessionsPane = document.getElementById('activity-sessions-pane');
        if (eventsPane) eventsPane.style.display = state.activityMode === 'events' ? 'block' : 'none';
        if (sessionsPane) sessionsPane.style.display = state.activityMode === 'sessions' ? 'block' : 'none';
        const me = document.getElementById('mode-events');
        const ms = document.getElementById('mode-sessions');
        if (me) me.setAttribute('aria-pressed', state.activityMode === 'events' ? 'true' : 'false');
        if (ms) ms.setAttribute('aria-pressed', state.activityMode === 'sessions' ? 'true' : 'false');
      }

      function setTab(tabName, pushToHistory = true, customPath = null) {
        if (tabName === 'sessions') {
          tabName = 'activity';
          state.activityMode = 'sessions';
        }
        if (!routes[tabName] && tabName !== 'overview') tabName = 'overview';
        state.activeTab = tabName;

        document.querySelectorAll('.nav-item a').forEach(a => {
          a.classList.toggle('active', a.dataset.tab === tabName);
        });
        document.querySelectorAll('.view-pane').forEach(p => {
          p.style.display = p.id === 'view-' + tabName ? 'block' : 'none';
        });
        applyActivityMode();

        const pageTitle = routes[tabName]?.title || 'vAIvar Central';
        document.title = pageTitle;
        const targetPath = customPath || (routes[tabName]?.path || '/overview') + serializeQuery();

        if (pushToHistory) {
          const currentUrl = window.location.pathname + window.location.search;
          if (currentUrl !== targetPath) {
            window.history.pushState({ tab: tabName, path: targetPath }, pageTitle, targetPath);
          }
        }

        if (tabName === 'settings') loadSettings();
        if (tabName === 'overview') setTimeout(renderThreatChart, 50);
        document.querySelector('.app-shell')?.classList.remove('nav-open');
      }

      function handleRoute() {
        let path = window.location.pathname || '/';
        if (path.length > 1 && path.endsWith('/')) {
          path = path.slice(0, -1);
        }

        let hash = window.location.hash || '';
        if (hash.startsWith('#')) hash = hash.slice(1);
        if (hash.startsWith('/')) hash = hash.slice(1);

        const params = new URLSearchParams(window.location.search);

        if (path.startsWith('/nodes/') && path.length > 7) {
          const siteId = decodeURIComponent(path.slice(7));
          setTab('honeypots', false, '/nodes/' + siteId);
          setTimeout(() => openNodeDrawer(siteId, false), 150);
          return;
        }
        if (hash.startsWith('nodes/') && hash.length > 6) {
          const siteId = decodeURIComponent(hash.slice(6));
          setTab('honeypots', false, '/nodes/' + siteId);
          setTimeout(() => openNodeDrawer(siteId, false), 150);
          return;
        }

        if (params.has('search')) {
          const q = params.get('search');
          if (els.globalSearch) {
            els.globalSearch.value = q;
            state.searchQuery = q;
          }
        }
        if (params.has('filter')) {
          const f = params.get('filter');
          state.eventFilter = f;
          document.querySelectorAll('[data-event-filter]').forEach(b => {
            b.classList.toggle('active', b.dataset.eventFilter === f);
          });
          updateFilterIndicator();
        } else {
          state.eventFilter = 'all';
          document.querySelectorAll('[data-event-filter]').forEach(b => {
            b.classList.toggle('active', b.dataset.eventFilter === 'all');
          });
          updateFilterIndicator();
        }
        if (params.has('conn')) state.connFilter = params.get('conn');
        if (params.has('proto')) state.protoFilter = params.get('proto');
        if (params.get('mode') === 'sessions') state.activityMode = 'sessions';
        if (params.has('section')) state.settingsSection = params.get('section');

        if (path === '/honeypots' || path === '/nodes' || hash === 'honeypots') {
          setTab('honeypots', false);
        } else if (path === '/activity' || path === '/threats' || hash === 'activity' || hash === 'threats') {
          setTab('activity', false);
        } else if (path === '/sessions' || hash === 'sessions') {
          state.activityMode = 'sessions';
          setTab('activity', false, '/sessions');
        } else if (path === '/settings' || hash === 'settings') {
          setTab('settings', false);
        } else {
          setTab('overview', false, path === '/' ? '/' : '/overview');
        }
      }

      window.addEventListener('popstate', handleRoute);
      window.addEventListener('hashchange', handleRoute);

      document.querySelectorAll('.nav-item a').forEach(a => {
        a.addEventListener('click', (e) => {
          if (e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) return;
          e.preventDefault();
          setTab(a.dataset.tab, true);
        });
      });

      document.getElementById('link-view-all-activity')?.addEventListener('click', (e) => {
        if (e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) return;
        e.preventDefault();
        setTab('activity', true);
      });

      // Data Loaders
      function connectionStatus(n) {
        if (n.last_contacted_at_ms == null) return 'waiting';
        if ((Date.now() - Number(n.last_contacted_at_ms)) > NODE_STALE_MS) return 'delayed';
        return 'connected';
      }

      function statusLabel(status) {
        if (status === 'waiting') return __loc.t('status_waiting');
        if (status === 'delayed') return __loc.t('status_delayed');
        return __loc.t('status_connected');
      }

      async function fetchMe() {
        const { ok, body } = await apiFetch('/me');
        const chip = document.getElementById('user-chip');
        if (ok && body) {
          state.me = body;
          state.mePermissions = Array.isArray(body.permissions) ? body.permissions : [];
          // Settings (incl. Users) is admin+; Infrastructure/system is superadmin.
          const canUsers = state.mePermissions.includes('manage_integrations');
          const canSystem = state.mePermissions.includes('manage_system');
          const usersPanel = document.getElementById('settings-users');
          if (usersPanel) usersPanel.style.display = canUsers ? '' : 'none';
          const sysPanel = document.querySelector('.settings-subnav a[data-settings-section="infrastructure"]');
          if (sysPanel && !canSystem && !state.me.dev_mode) sysPanel.style.display = 'none';
          const sub = document.getElementById('accounts-panel-sub');
          if (sub) {
            const who = body.email ? String(body.email) : (body.dev_mode ? 'Local (dev mode)' : 'unknown');
            const roleTxt = body.role ? ('as ' + String(body.role)) : 'not signed in';
            sub.textContent = 'Signed in as ' + who + ' ' + roleTxt + '.';
          }
          if (chip) {
            if (body.dev_mode) chip.textContent = 'Local';
            else if (body.email) chip.textContent = String(body.email) + (body.role ? ' · ' + String(body.role) : '');
            else if (body.role) chip.textContent = String(body.role);
            else chip.textContent = '—';
          }
        } else if (chip) chip.textContent = 'Local';
      }

      async function fetchStats() {
        const { ok, body } = await apiFetch('/stats');
        if (ok && body) {
          state.stats = body;
          els.statNodes.textContent = formatNumber(body.nodes);
          els.statEvents.textContent = formatNumber(body.events);
          els.statFlags.textContent = formatNumber(body.flags);
          els.statSessions.textContent = formatNumber(body.sessions);
          els.badgeNodeCount.textContent = formatNumber(body.nodes);

          if (typeof state.previousFlags === 'number' && body.flags > state.previousFlags) {
            const diff = body.flags - state.previousFlags;
            showToast('🚨 ALERTA: ¡Ataque detectado en el honeypot! ' + diff + ' flag(s) capturada(s).', 'error');
          }
          state.previousFlags = body.flags;

          if (els.statFlagsBadge) {
            if (body.flags > 0) {
              els.statFlagsBadge.textContent = '🚨 ' + body.flags + ' ' + __loc.t('kpi_flags');
              els.statFlagsBadge.className = 'kpi-badge critical';
            } else {
              els.statFlagsBadge.textContent = 'None yet';
              els.statFlagsBadge.className = 'kpi-badge positive';
            }
          }

          els.footerUptime.textContent = formatUptime(body.uptime_seconds);
          els.footerStorage.textContent = formatBytes(body.size_bytes);
          const infra = __loc.t('infra_unavailable') + ' · uptime ' + formatUptime(body.uptime_seconds) + ' · store ' + formatBytes(body.size_bytes);
          const ov = document.getElementById('overview-infra');
          const si = document.getElementById('settings-infra-line');
          if (ov) ov.textContent = infra;
          if (si) si.textContent = infra;

          updateThreatStatusUI();
          renderOverviewAttention();
        }
      }

      async function fetchNodes() {
        const { ok, body } = await apiFetch('/nodes');
        if (ok && body && Array.isArray(body.nodes)) {
          state.nodes = body.nodes;
          els.badgeNodeCount.textContent = formatNumber(state.nodes.length);
          const connected = state.nodes.filter((n) => connectionStatus(n) === 'connected').length;
          if (els.statNodesStatus) {
            els.statNodesStatus.textContent = state.nodes.length ? (connected + ' ' + __loc.t('status_connected')) : '—';
            els.statNodesStatus.className = 'kpi-badge ' + (state.nodes.length && connected === state.nodes.length ? 'positive' : 'subtle');
          }
          renderNodes();
          renderOverviewAttention();
        }
      }

      async function fetchTemplates() {
        const { ok, body } = await apiFetch('/templates');
        if (ok && body && Array.isArray(body.templates)) state.templates = body.templates;
      }

      async function fetchEvents() {
        const { ok, body } = await apiFetch('/events?limit=100');
        if (ok && body && Array.isArray(body.events)) {
          state.events = body.events;
          renderActivity();
          renderThreatChart();
          renderNodes();
          updateThreatStatusUI();
        }
      }

      async function fetchSessions() {
        const { ok, body } = await apiFetch('/activity');
        if (ok && body) {
          state.activityRows = body.activity || [];
          renderSessions();
        }
      }

      async function fetchAll() {
        els.btnManualRefresh.classList.add('spinning');
        await Promise.all([fetchMe(), fetchStats(), fetchNodes(), fetchTemplates(), fetchEvents(), fetchSessions()]);
        state.lastRefresh = Date.now();
        const fu = document.getElementById('footer-updated');
        if (fu) fu.textContent = (__loc.t('updated_ago') || 'Updated {time}').replace('{time}', timeAgo(state.lastRefresh));
        setTimeout(() => els.btnManualRefresh.classList.remove('spinning'), 500);
      }

      function nodeIdentityHtml(n) {
        const hasCustomName = Boolean(n.name && n.name.trim());
        const title = hasCustomName ? escapeHtml(n.name.trim()) : (escapeHtml(n.host) + ':' + escapeHtml(n.port));
        const subtitle = hasCustomName ? ('<div style="font-size:0.75rem; color:var(--text-soft); margin-top:-2px;">' + escapeHtml(n.host) + ':' + escapeHtml(n.port) + '</div>') : '';
        return '<div class="node-ident">' +
          '<div class="node-avatar">' + (n.channel === 'encrypted' ? 'ENC' : 'LEG') + '</div>' +
          '<div class="node-title-wrap">' +
            '<h3>' + title + '</h3>' +
            subtitle +
            '<div class="node-site-pill" title="' + escapeHtml(__loc.t('copy_site_id')) + '" onclick="event.stopPropagation(); copyToClipboard(\\'' + escapeHtml(n.site_id) + '\\', \\'Site ID\\')">' +
              '<span>ID: ' + escapeHtml(n.site_id ? n.site_id.slice(0, 8) + '…' : '—') + '</span>' +
            '</div>' +
          '</div>' +
        '</div>';
      }

      function profileLabel(profile) {
        const keys = { all: 'profile_all', http: 'profile_http', wiki: 'profile_wiki', openapi: 'profile_openapi', mcp: 'profile_mcp' };
        return keys[profile] ? __loc.t(keys[profile]) : 'Unknown';
      }

      function renderOverviewStrip(n) {
        const status = connectionStatus(n);
        const statusClass = status === 'connected' ? 'online' : (status === 'waiting' ? 'stale' : 'stale');
        const notesSnippet = n.notes && n.notes.trim()
          ? '<div style="font-size:0.72rem; color:var(--text-soft); background:var(--color-bg); border-left:3px solid var(--cyan); padding:4px 8px; border-radius:var(--radius-sm); margin:6px 0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(n.notes) + '">' + escapeHtml(n.notes) + '</div>'
          : '';
        return '<div class="node-card" data-site-id="' + escapeHtml(n.site_id) + '">' +
          '<div class="node-card-head">' + nodeIdentityHtml(n) +
            '<span class="node-badge ' + statusClass + '">' + escapeHtml(statusLabel(status)) + '</span>' +
          '</div>' +
          notesSnippet +
          '<div class="node-actions">' +
            '<button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); openNodeDrawer(\\'' + escapeHtml(n.site_id) + '\\')">' + escapeHtml(__loc.t('btn_open')) + '</button>' +
          '</div></div>';
      }

      function renderHoneypotCard(n) {
        const status = connectionStatus(n);
        const statusClass = status === 'connected' ? 'online' : 'stale';
        const last = n.last_contacted_at_ms == null ? statusLabel('waiting') : timeAgo(n.last_contacted_at_ms);
        const sid = escapeHtml(n.site_id);
        const notesHtml = n.notes && n.notes.trim()
          ? '<div style="font-size:0.75rem; color:var(--text-soft); background:var(--color-bg); border-left:3px solid var(--cyan); padding:6px 10px; border-radius:var(--radius-sm); margin:10px 0 6px; line-height:1.4; max-height:48px; overflow:hidden; text-overflow:ellipsis;" title="' + escapeHtml(n.notes) + '">' +
              '<span style="font-weight:600; color:var(--cyan); font-size:0.68rem; text-transform:uppercase; letter-spacing:0.04em; display:block; margin-bottom:2px;">Operator Note</span>' +
              escapeHtml(n.notes) +
            '</div>'
          : '';
        return '<div class="node-card" data-site-id="' + sid + '">' +
          '<div class="node-card-head">' + nodeIdentityHtml(n) +
            '<span class="node-badge ' + statusClass + '">' + escapeHtml(statusLabel(status)) + '</span>' +
          '</div>' +
          '<div class="node-details-list">' +
            '<div class="node-detail-item"><span class="detail-k">' + escapeHtml(__loc.t('label_control_port')) + '</span><span class="detail-v">' + escapeHtml('HTTP · ' + (n.channel === 'encrypted' ? 'AES-256-GCM' : 'legacy') + ':' + n.port) + '</span></div>' +
            '<div class="node-detail-item"><span class="detail-k">' + escapeHtml(__loc.t('label_exposed_port')) + '</span><span class="detail-v">' + escapeHtml(n.honeypot_port ?? 'Unknown') + '</span></div>' +
            '<div class="node-detail-item"><span class="detail-k">' + escapeHtml(__loc.t('label_simulates')) + '</span><span class="detail-v">' + escapeHtml(profileLabel(n.service_profile)) + '</span></div>' +
            '<div class="node-detail-item"><span class="detail-k">Last contact</span><span class="detail-v">' + escapeHtml(last) + '</span></div>' +
          '</div>' +
          notesHtml +
          '<div class="node-actions">' +
            '<button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); openNodeDrawer(\\'' + sid + '\\')">' + escapeHtml(__loc.t('btn_open')) + '</button>' +
            '<div class="card-overflow">' +
              '<button class="btn btn-outline btn-sm" aria-haspopup="menu" aria-label="More" onclick="event.stopPropagation(); toggleOverflow(this)">⋯</button>' +
              '<div class="overflow-menu" role="menu">' +
                '<button type="button" role="menuitem" onclick="event.stopPropagation(); executeNodeCommand(\\'' + sid + '\\', \\'restart\\')">Restart</button>' +
                '<button type="button" role="menuitem" onclick="event.stopPropagation(); executeNodeCommand(\\'' + sid + '\\', \\'rotate_challenges\\')">Rotate</button>' +
                '<button type="button" role="menuitem" onclick="event.stopPropagation(); unenrollNode(\\'' + sid + '\\')">' + escapeHtml(__loc.t('btn_unenroll')) + '</button>' +
              '</div>' +
            '</div>' +
          '</div></div>';
      }

      window.toggleOverflow = function(btn) {
        document.querySelectorAll('.overflow-menu.open').forEach((m) => { if (m !== btn.nextElementSibling) m.classList.remove('open'); });
        btn.nextElementSibling?.classList.toggle('open');
      };

      function emptyFleetHtml() {
        return '<div class="empty-box">' +
          '<div class="empty-title">' + escapeHtml(__loc.t('empty_fleet_title')) + '</div>' +
          '<div class="empty-desc">' + escapeHtml(__loc.t('empty_fleet_body')) + '</div>' +
          '<div class="empty-desc">' + escapeHtml(__loc.t('empty_fleet_helper')) + '</div>' +
          '<button class="btn btn-primary" onclick="openEnrollModal()">' + escapeHtml(__loc.t('btn_add_honeypot')) + '</button>' +
        '</div>';
      }

      function renderOverviewAttention() {
        const el = document.getElementById('overview-attention');
        if (!el) return;
        const flags = Number(state.stats?.flags || 0);
        if (flags > 0) {
          el.hidden = false;
          el.className = 'attention-banner attack-alarm';
          el.innerHTML = '<div style="display:flex; align-items:center; gap:14px;">' +
            '<div style="font-size:1.6rem; line-height:1;">🚨</div>' +
            '<div>' +
              '<strong style="color:#ef4444; font-size:0.95rem; text-transform:uppercase; letter-spacing:0.04em;">Honeypot Compromise Detected (' + flags + ' flag' + (flags > 1 ? 's' : '') + ')</strong>' +
              '<p style="color:var(--color-text-main); margin-top:2px;">Hostile agent or attacker triggered capture-the-flag traps. Review payload telemetry immediately.</p>' +
            '</div>' +
          '</div>' +
          '<a href="/activity?filter=flag" class="btn btn-primary btn-sm" style="background:#dc2626; border-color:#ef4444; color:#fff; font-weight:700; white-space:nowrap;" onclick="reviewAttacksAlarm(event)">' +
            'Review Attacks (' + flags + ')' +
          '</a>';
          return;
        }
        el.hidden = true;
        el.className = 'attention-banner';
        el.innerHTML = '';
      }

      window.reviewAttacksAlarm = function(e) {
        if (e && e.preventDefault) e.preventDefault();
        state.eventFilter = 'flag';
        updateFilterIndicator();
        renderActivity();
        setTab('activity', true);
      };

      function renderNodes() {
        const q = state.searchQuery.toLowerCase();
        const filtered = state.nodes.filter(n => {
          const st = connectionStatus(n);
          if (state.connFilter !== 'all' && st !== state.connFilter) return false;
          if (state.protoFilter !== 'all' && (n.channel || 'legacy') !== state.protoFilter) return false;
          if (q) {
            const matchName = (n.name || '').toLowerCase().includes(q);
            const matchNotes = (n.notes || '').toLowerCase().includes(q);
            const matchSite = (n.site_id || '').toLowerCase().includes(q);
            const matchHost = (n.host || '').toLowerCase().includes(q);
            const matchPort = String(n.port || '').includes(q) || String(n.honeypot_port || '').includes(q);
            const matchProfile = String(n.service_profile || '').toLowerCase().includes(q);
            if (!matchName && !matchNotes && !matchSite && !matchHost && !matchPort && !matchProfile) return false;
          }
          return true;
        });

        if (!state.nodes.length) {
          els.fullNodesGrid.innerHTML = emptyFleetHtml();
          els.overviewNodesGrid.innerHTML = emptyFleetHtml();
          return;
        }
        els.fullNodesGrid.innerHTML = filtered.length
          ? filtered.map(renderHoneypotCard).join('')
          : '<div class="empty-box"><div class="empty-title">' + escapeHtml(__loc.t('empty_filter_title')) + '</div></div>';
        els.overviewNodesGrid.innerHTML = state.nodes.slice(0, 4).map(renderOverviewStrip).join('');
      }

      // Render Activity Feed
      function renderActivity() {
        const filter = state.eventFilter;
        const q = state.searchQuery.toLowerCase();

        const filtered = state.events.filter(e => {
          const type = (e.type || '').toLowerCase();
          const isAtk = type.includes('flag') || type.includes('canary') || e.severity === 'critical' || e.severity === 'high';
          if (filter === 'attacks' && !isAtk) return false;
          if (filter === 'session' && !type.includes('session')) return false;
          if (filter === 'flag' && !type.includes('flag')) return false;
          if (filter === 'command' && !type.includes('command')) return false;
          if (filter === 'canary' && !type.includes('canary')) return false;
          if (q) {
            const matchType = type.includes(q);
            const matchSess = (e.session_id || '').toLowerCase().includes(q);
            const matchSite = (e.site_id || '').toLowerCase().includes(q);
            const matchSummary = (e.summary || '').toLowerCase().includes(q);
            const matchIp = (e.attacker_ip || '').toLowerCase().includes(q);
            if (!matchType && !matchSess && !matchSite && !matchSummary && !matchIp) return false;
          }
          return true;
        });

        // Overview mini feed
        const miniEvents = filtered.slice(0, 5);
        els.overviewActivityList.innerHTML = miniEvents.length ? miniEvents.map(e => {
          const badgeClass = getBadgeClass(e.type);
          const isAttack = (e.type || '').toLowerCase().includes('flag') || (e.type || '').toLowerCase().includes('canary');
          const node = state.nodes.find(n => n.site_id === e.site_id);
          const nodeLabel = node?.name ? node.name : (e.site_id ? ('Node ' + e.site_id.slice(0, 8)) : 'Sensor');
          return '<div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:var(--color-bg); border-radius:var(--radius-md); border:1px solid ' + (isAttack ? 'rgba(239,68,68,0.4)' : 'var(--color-border)') + ';">' +
            '<div style="display:flex; align-items:center; gap:10px; min-width:0;">' +
              '<span class="event-badge ' + badgeClass + '">' + (isAttack ? '🚨 ' : '') + escapeHtml(e.type) + '</span>' +
              '<div style="min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
                (e.summary ? ('<span style="font-size:0.75rem; color:' + (isAttack ? '#fca5a5' : 'var(--color-text-main)') + '; font-weight:600;">' + escapeHtml(e.summary) + '</span> · ') : '') +
                '<span class="mono" style="font-size:0.75rem; color:var(--text-soft);">' + escapeHtml(nodeLabel) + '</span>' +
              '</div>' +
            '</div>' +
            '<span class="mono" style="font-size:0.7rem; color:var(--text-dim); flex-shrink:0;">' + escapeHtml(timeAgo(e.ts)) + '</span>' +
          '</div>';
        }).join('') : '<div class="empty-box" style="padding:20px 0;"><div class="empty-title">' + escapeHtml(__loc.t('empty_events_title')) + '</div><div class="empty-desc">' + escapeHtml(__loc.t('empty_events_body')) + '</div></div>';

        // Full Activity Table
        els.activityTableBody.innerHTML = filtered.length ? filtered.map((e, idx) => {
          const badgeClass = getBadgeClass(e.type);
          const isAttack = (e.type || '').toLowerCase().includes('flag') || (e.type || '').toLowerCase().includes('canary') || e.severity === 'critical' || e.severity === 'high';
          const rowClass = isAttack ? ' class="attack-row"' : '';
          let parsedJson = null;
          if (typeof e.payload === 'object' && e.payload !== null) {
            parsedJson = e.payload;
          } else {
            try { parsedJson = JSON.parse(e.payload); } catch {}
          }
          const formattedPayload = parsedJson ? JSON.stringify(parsedJson, null, 2) : (e.payload || 'No payload content');
          const isPayloadOpen = openPayloads.has(idx);

          // Honeypot node name if known
          const node = state.nodes.find(n => n.site_id === e.site_id);
          const nodeDisplay = node ? (node.name ? (node.name + ' (' + node.host + ':' + node.port + ')') : (node.host + ':' + node.port)) : (e.site_id || 'Unknown Sensor');

          // Summary and descriptive intelligence
          let detailHtml = '';
          if (e.summary) {
            const sev = (e.severity || 'info').toUpperCase();
            const sevColor = sev === 'CRITICAL' ? '#ef4444' : (sev === 'HIGH' ? '#f97316' : (sev === 'MEDIUM' ? '#eab308' : 'var(--cyan)'));
            detailHtml = '<div style="margin-bottom:8px; line-height:1.4;">' +
              '<div style="font-size:0.83rem; font-weight:600; color:' + (isAttack ? '#fca5a5' : 'var(--color-text-main)') + '; margin-bottom:5px;">' +
                (isAttack ? '🚨 ' : '') + escapeHtml(e.summary) +
              '</div>' +
              '<div style="display:flex; flex-wrap:wrap; gap:6px; align-items:center;">' +
                '<span class="cap-pill" style="font-size:0.68rem; font-weight:700; border-color:' + sevColor + '; color:' + sevColor + ';">' + escapeHtml(sev) + '</span>' +
                '<span class="cap-pill" style="font-size:0.68rem; background:rgba(255,255,255,0.04); color:var(--text-soft);">Honeypot: ' + escapeHtml(nodeDisplay) + '</span>' +
                (e.attacker_ip ? '<span class="cap-pill" style="font-size:0.68rem; background:rgba(255,255,255,0.04); color:var(--text-soft);">IP: ' + escapeHtml(e.attacker_ip) + '</span>' : '') +
                (e.classification ? '<span class="cap-pill" style="font-size:0.68rem; background:rgba(255,255,255,0.04); color:var(--text-soft);">Agent: ' + escapeHtml(e.classification) + '</span>' : '') +
                (e.trap_path ? '<span class="cap-pill mono" style="font-size:0.68rem; background:rgba(255,255,255,0.04); color:var(--cyan);">' + escapeHtml(e.trap_path) + '</span>' : '') +
              '</div>' +
            '</div>';
          } else {
            detailHtml = '<div style="font-size:0.75rem; color:var(--text-soft); margin-bottom:6px;">Honeypot: ' + escapeHtml(nodeDisplay) + '</div>';
          }

          return '<tr' + rowClass + '>' +
            '<td class="mono" style="white-space:nowrap; color:var(--text-dim);">' + escapeHtml(formatDate(e.ts)) + '<br><span style="font-size:0.68rem; color:' + (isAttack ? '#ef4444' : 'var(--cyan)') + ';">' + escapeHtml(timeAgo(e.ts)) + (isAttack ? ' · 🚨 ATTACK' : '') + '</span></td>' +
            '<td><span class="event-badge ' + badgeClass + '">' + (isAttack ? '🚨 ' : '') + escapeHtml(e.type) + '</span></td>' +
            '<td class="mono">' +
              (e.session_id ? '<span style="color:' + (isAttack ? '#ef4444' : 'var(--cyan-glow)') + '; font-weight:' + (isAttack ? '700' : 'normal') + ';">' + escapeHtml(e.session_id) + '</span>' : '<span style="color:var(--text-dim);">—</span>') +
            '</td>' +
            '<td>' +
              detailHtml +
              '<button class="payload-toggle" onclick="togglePayload(' + idx + ')">' +
                '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg> Inspect Payload' +
              '</button>' +
              '<div class="payload-box" id="payload-' + idx + '" style="display:' + (isPayloadOpen ? 'block' : 'none') + ';">' +
                '<div class="payload-bar">' +
                  '<span class="payload-tag">JSON Payload</span>' +
                  '<button class="payload-copy-btn" onclick="copyPayload(' + idx + ')">Copy JSON</button>' +
                '</div>' +
                '<pre style="margin:0; overflow-x:auto;"><code id="payload-' + idx + '-code">' + escapeHtml(formattedPayload) + '</code></pre>' +
              '</div>' +
            '</td>' +
            '<td style="text-align:right;">' +
              '<button class="btn btn-outline btn-sm" data-session="' + escapeHtml(e.session_id || '') + '" onclick="filterBySession(this)">Filter Session</button>' +
            '</td>' +
          '</tr>';
        }).join('') : '<tr><td colspan="5"><div class="empty-box"><div class="empty-title">No events match filter</div></div></td></tr>';
      }

      function getBadgeClass(type = '') {
        const t = type.toLowerCase();
        if (t.includes('flag')) return 'flag';
        if (t.includes('session')) return 'session';
        if (t.includes('command')) return 'command';
        if (t.includes('canary')) return 'canary';
        return 'generic';
      }

      window.copyPayload = function(idx) {
        const el = document.getElementById('payload-' + idx + '-code');
        if (el) copyToClipboard(el.textContent, 'Payload JSON');
      };

      const openPayloads = new Set();
      window.togglePayload = function(idx) {
        if (openPayloads.has(idx)) {
          openPayloads.delete(idx);
        } else {
          openPayloads.add(idx);
        }
        const el = document.getElementById('payload-' + idx);
        if (el) {
          el.style.display = openPayloads.has(idx) ? 'block' : 'none';
        }
      };

      window.filterBySession = function(arg) {
        const sessId = typeof arg === 'string' ? arg : (arg ? arg.getAttribute('data-session') : '');
        if (!sessId) return;
        if (els.globalSearch) els.globalSearch.value = sessId;
        state.searchQuery = sessId;
        updateFilterIndicator();
        setTab('activity');
        renderActivity();
      };

      // Render Sessions as a compact table (scales to hundreds of sessions).
      function renderSessions() {
        const sessionMap = new Map();
        const rows = state.activityRows || [];
        for (const e of rows) {
          const sid = e.session_id;
          if (!sid) continue;
          const key = (e.site_id || '') + '\\0' + sid;
          if (!sessionMap.has(key)) {
            sessionMap.set(key, {
              id: sid,
              site_id: e.site_id || '',
              last_ts: e.ts,
              count: 0,
              agentClass: e.classification || 'unknown',
              confidence: Math.round((e.confidence ?? 0) * 100),
              tooling: Array.isArray(e.tooling) ? e.tooling : [],
            });
          }
          const s = sessionMap.get(key);
          s.count++;
          if (e.ts > s.last_ts) s.last_ts = e.ts;
        }

        const sessions = Array.from(sessionMap.values());
        const tbody = document.getElementById('sessions-grid');
        if (!tbody) return;
        if (!sessions.length) {
          tbody.innerHTML = '<tr><td colspan="8" class="empty-box"><div class="empty-title">' + escapeHtml(__loc.t('empty_sessions_title')) + '</div></td></tr>';
          return;
        }
        tbody.innerHTML = sessions.map(s => {
          const confClass = s.confidence > 70 ? 'critical' : s.confidence > 40 ? 'warn' : 'positive';
          const tooling = s.tooling.length
            ? s.tooling.map(t => '<span class="cap-pill">' + escapeHtml(t) + '</span>').join(' ')
            : '<span style="color:var(--text-dim);">—</span>';
          return '<tr>' +
            '<td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(s.id) + '">' + escapeHtml(s.id) + '</td>' +
            '<td class="mono">' + escapeHtml(s.site_id || '—') + '</td>' +
            '<td>' + escapeHtml(s.agentClass) + '</td>' +
            '<td><span class="kpi-badge ' + confClass + '">' + s.confidence + '%</span></td>' +
            '<td>' + s.count + '</td>' +
            '<td>' + escapeHtml(timeAgo(s.last_ts)) + '</td>' +
            '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + tooling + '</td>' +
            '<td><button class="btn btn-outline btn-sm" data-session="' + escapeHtml(s.id) + '" onclick="filterBySession(this)">' + escapeHtml(__loc.t('btn_open')) + '</button></td>' +
          '</tr>';
        }).join('');
      }

      // Threat Volume Canvas Chart
      function renderThreatChart() {
        const canvas = els.threatChartCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const rect = canvas.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const w = rect.width;
        const h = rect.height;

        ctx.clearRect(0, 0, w, h);

        // Compute 12 time buckets from state.events
        const buckets = 12;
        const counts = new Array(buckets).fill(0);
        const now = Date.now();
        const interval = 60000; // 1 minute per bucket

        state.events.forEach(e => {
          const age = now - (e.ts || now);
          const idx = Math.floor(age / interval);
          if (idx >= 0 && idx < buckets) {
            counts[buckets - 1 - idx]++;
          }
        });

        if (counts.every(c => c === 0)) {
          const label = document.getElementById('chart-sync-label');
          if (label) label.textContent = __loc.t('empty_events_title');
          return;
        }

        const maxVal = Math.max(...counts, 4);
        const paddingBottom = 30;
        const paddingTop = 20;
        const paddingLeft = 30;
        const paddingRight = 20;
        const chartW = w - paddingLeft - paddingRight;
        const chartH = h - paddingTop - paddingBottom;

        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const gridColor = isDark ? '#222226' : '#e2e8f0';
        const textColor = isDark ? '#a1a1aa' : '#64748b';
        const strokeColor = isDark ? '#818cf8' : '#6366f1';
        const dotBorder = isDark ? '#121215' : '#ffffff';

        // Grid lines
        ctx.strokeStyle = gridColor;
        ctx.lineWidth = 1;
        for (let i = 0; i <= 3; i++) {
          const y = paddingTop + (chartH / 3) * i;
          ctx.beginPath();
          ctx.moveTo(paddingLeft, y);
          ctx.lineTo(w - paddingRight, y);
          ctx.stroke();

          ctx.fillStyle = textColor;
          ctx.font = '10px JetBrains Mono';
          ctx.fillText(Math.round(maxVal - (maxVal / 3) * i), 8, y + 3);
        }

        // Points
        const stepX = chartW / (buckets - 1);
        const points = counts.map((cnt, i) => {
          const x = paddingLeft + i * stepX;
          const y = paddingTop + chartH - (cnt / maxVal) * chartH;
          return { x, y };
        });

        // Flat Subtle Fill
        const grad = ctx.createLinearGradient(0, paddingTop, 0, paddingTop + chartH);
        if (isDark) {
          grad.addColorStop(0, 'rgba(129, 140, 248, 0.22)');
          grad.addColorStop(1, 'rgba(129, 140, 248, 0.01)');
        } else {
          grad.addColorStop(0, 'rgba(99, 102, 241, 0.16)');
          grad.addColorStop(1, 'rgba(99, 102, 241, 0.02)');
        }

        ctx.beginPath();
        ctx.moveTo(points[0].x, paddingTop + chartH);
        points.forEach(p => ctx.lineTo(p.x, p.y));
        ctx.lineTo(points[points.length - 1].x, paddingTop + chartH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();

        // Flat Crisp Line
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 1; i < points.length; i++) {
          const xc = (points[i].x + points[i - 1].x) / 2;
          const yc = (points[i].y + points[i - 1].y) / 2;
          ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
        }
        ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 2;
        ctx.stroke();

        // Dots
        points.forEach(p => {
          ctx.beginPath();
          ctx.arc(p.x, p.y, 3.5, 0, Math.PI * 2);
          ctx.fillStyle = strokeColor;
          ctx.fill();
          ctx.strokeStyle = dotBorder;
          ctx.lineWidth = 2;
          ctx.stroke();
        });
      }

      window.addEventListener('resize', () => {
        if (state.activeTab === 'overview') renderThreatChart();
      });

      // Node Commands
      window.executeNodeCommand = async function(siteId, command) {
        if (!confirm('Execute remote command "' + command + '" on node ' + siteId + '?')) return;
        showToast('Sending command ' + command + '...', 'info');
        const { ok, body } = await apiFetch('/nodes/' + encodeURIComponent(siteId) + '/commands/' + encodeURIComponent(command), { method: 'POST' });
        if (ok) {
          showToast('Command executed successfully: ' + (body.outcome?.message || 'Queued'), 'success');
          fetchAll();
        } else {
          showToast('Command failed: ' + (body?.error || 'Unknown error'), 'error');
        }
      };

      // Unenroll / Delete Node
      window.unenrollNode = async function(siteId) {
        if (!confirm('Are you sure you want to unenroll and remove honeypot node ' + siteId + '?')) return;
        const { ok, body } = await apiFetch('/nodes/' + encodeURIComponent(siteId), { method: 'DELETE' });
        if (ok) {
          showToast('Node removed from central registry.', 'success');
          fetchAll();
          closeDrawer();
        } else {
          showToast('Failed to remove node: ' + (body?.error || 'Unauthorized'), 'error');
        }
      };

      // Save Honeypot Custom Name and Operator Notes
      window.saveNodeMetadata = async function(siteId) {
        const nameInput = document.getElementById('node-meta-name');
        const notesInput = document.getElementById('node-meta-notes');
        const btn = document.getElementById('btn-save-node-meta');
        if (btn) btn.disabled = true;

        const name = nameInput ? nameInput.value.trim() : '';
        const notes = notesInput ? notesInput.value.trim() : '';

        const { ok, body } = await apiFetch('/nodes/' + encodeURIComponent(siteId) + '/metadata', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name || null, notes: notes || null }),
        });

        if (btn) btn.disabled = false;

        if (ok) {
          showToast('Honeypot details saved successfully.', 'success');
          const node = state.nodes.find(n => n.site_id === siteId);
          if (node) {
            node.name = name || null;
            node.notes = notes || null;
          }
          renderNodes();
          const hasCustomName = Boolean(name);
          els.drawerNodeTitle.textContent = hasCustomName ? name : ((node?.host || 'Honeypot') + ':' + (node?.port || '—'));
          els.drawerNodeSite.textContent = (hasCustomName ? ((node?.host || '') + ':' + (node?.port || '') + ' · ') : '') + 'Site ID: ' + siteId;
        } else {
          showToast('Failed to save details: ' + (body?.error || 'Unknown error'), 'error');
        }
      };

      window.configureNode = async function(siteId) {
        const portInput = document.getElementById('node-config-port');
        const profileInput = document.getElementById('node-config-profile');
        const port = Number(portInput?.value);
        const profile = profileInput?.value;
        if (!Number.isInteger(port) || port < 1 || port > 65535 || !profile) {
          showToast('Use a valid exposed port and service profile.', 'error');
          return;
        }
        const btn = document.getElementById('btn-save-node-config');
        if (btn) btn.disabled = true;
        const response = await apiFetch('/nodes/' + encodeURIComponent(siteId) + '/commands/configure_honeypot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ port, profile }),
        });
        if (btn) btn.disabled = false;
        if (!response.ok) {
          showToast('Could not update honeypot: ' + (response.body?.error || 'Unknown error'), 'error');
          return;
        }
        const result = response.body?.outcome?.outcome;
        showToast('Honeypot updated to ' + port + ' / ' + profileLabel(result?.profile || profile) + '.', 'success');
        await fetchAll();
        openNodeDrawer(siteId, false);
      };

      window.applyNodeTemplate = async function(siteId) {
        const input = document.getElementById('node-config-template');
        const raw = input?.value || '';
        const parts = raw.split('|');
        const template_id = parts[0];
        const version = Number(parts[1]);
        if (!template_id || !Number.isInteger(version) || version < 1) {
          showToast('Choose a valid template.', 'error');
          return;
        }
        const btn = document.getElementById('btn-apply-node-template');
        if (btn) btn.disabled = true;
        const response = await apiFetch('/nodes/' + encodeURIComponent(siteId) + '/commands/apply_template', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ template_id, version }),
        });
        if (btn) btn.disabled = false;
        if (!response.ok) {
          showToast('Could not apply template: ' + (response.body?.error || 'Unknown error'), 'error');
          return;
        }
        showToast('Template applied: ' + template_id + ' v' + version + '.', 'success');
        await fetchAll();
        openNodeDrawer(siteId, false);
      };

      // Node Detail Drawer
      window.openNodeDrawer = async function(siteId, updateUrl = true) {
        if (updateUrl) {
          const url = '/nodes/' + encodeURIComponent(siteId);
          window.history.pushState({ tab: 'honeypots', siteId }, 'Node ' + siteId + ' | vAIvar Central', url);
          document.title = 'Node ' + (siteId.length > 8 ? siteId.slice(0, 8) + '…' : siteId) + ' | vAIvar Central';
        }
        els.drawerNodeTitle.textContent = 'Loading Node...';
        els.drawerNodeSite.textContent = 'Site ID: ' + siteId;
        els.drawerContent.innerHTML = '<div class="empty-box"><div class="empty-title">Fetching verified telemetry...</div></div>';
        els.drawerOverlay.classList.add('active');
        els.nodeDrawer.classList.add('active');

        const { ok, body } = await apiFetch('/nodes/' + encodeURIComponent(siteId));
        if (!ok || !body) {
          els.drawerContent.innerHTML = '<div class="empty-box"><div class="empty-title">Failed to load node specs</div></div>';
          return;
        }

        const n = body;
        const hasCustomName = Boolean(n.name && n.name.trim());
        els.drawerNodeTitle.textContent = hasCustomName ? n.name.trim() : ((n.host || 'Honeypot') + ':' + (n.port || '—'));
        els.drawerNodeSite.textContent = (hasCustomName ? (escapeHtml(n.host) + ':' + escapeHtml(n.port) + ' · ') : '') + 'Site ID: ' + n.site_id;

        const caps = Array.isArray(n.capabilities) ? n.capabilities : [];

        const last = n.last_contacted_at_ms == null ? statusLabel('waiting') : (timeAgo(n.last_contacted_at_ms) + ' (' + formatDate(n.last_contacted_at_ms) + ')');
        const sid = escapeHtml(n.site_id);
        const summary = '<div class="panel">' +
            '<div class="node-details-list" style="grid-template-columns:1fr;">' +
              '<div class="node-detail-item"><span class="detail-k">Site ID</span><span class="detail-v">' + sid + '</span></div>' +
              '<div class="node-detail-item"><span class="detail-k">Fingerprint</span><span class="detail-v">' + escapeHtml(n.token_fingerprint || '—') + '</span></div>' +
              '<div class="node-detail-item"><span class="detail-k">' + escapeHtml(__loc.t('label_control_port')) + '</span><span class="detail-v">HTTP · ' + escapeHtml((n.channel === 'encrypted' ? 'AES-256-GCM · ' : 'legacy · ') + n.host + ':' + n.port) + '</span></div>' +
              '<div class="node-detail-item"><span class="detail-k">' + escapeHtml(__loc.t('label_exposed_port')) + '</span><span class="detail-v">' + escapeHtml(n.honeypot_port ?? 'Unknown') + '</span></div>' +
              '<div class="node-detail-item"><span class="detail-k">' + escapeHtml(__loc.t('label_service_profile')) + '</span><span class="detail-v">' + escapeHtml(profileLabel(n.service_profile)) + '</span></div>' +
              '<div class="node-detail-item"><span class="detail-k">Registered</span><span class="detail-v">' + escapeHtml(formatDate(n.registered_at_ms)) + '</span></div>' +
              '<div class="node-detail-item"><span class="detail-k">Last contact</span><span class="detail-v">' + escapeHtml(last) + '</span></div>' +
            '</div>' +
            '<div class="node-caps" style="margin-top:12px;">' +
              caps.map(c => '<span class="cap-pill">' + escapeHtml(c) + '</span>').join('') +
            '</div>' +
          '</div>';
        const nodeMetaSection = '<div class="panel" style="margin-top:14px;">' +
            '<div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">' +
              '<h4 style="margin:0; font-size:0.9rem; font-weight:600; color:var(--color-text-main); display:flex; align-items:center; gap:8px;">' +
                '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>' +
                'Honeypot Customization' +
              '</h4>' +
              '<span class="cap-pill" style="font-size:0.68rem; color:var(--cyan); border-color:var(--cyan);">Database Persisted</span>' +
            '</div>' +
            '<div class="form-group" style="margin-bottom:12px;">' +
              '<label for="node-meta-name" style="font-size:0.8rem; font-weight:600; color:var(--text-soft); margin-bottom:4px; display:block;">Descriptive Name</label>' +
              '<input id="node-meta-name" type="text" style="width:100%; box-sizing:border-box; background:var(--color-bg); border:1px solid var(--color-border); border-radius:var(--radius-sm); padding:8px 10px; color:var(--color-text-main); font-size:0.85rem;" placeholder="e.g. Frankfurt VPC - Primary Wiki Sensor" value="' + escapeHtml(n.name || '') + '">' +
            '</div>' +
            '<div class="form-group" style="margin-bottom:12px;">' +
              '<label for="node-meta-notes" style="font-size:0.8rem; font-weight:600; color:var(--text-soft); margin-bottom:4px; display:block;">Operator & Intelligence Notes</label>' +
              '<textarea id="node-meta-notes" rows="3" style="width:100%; box-sizing:border-box; background:var(--color-bg); border:1px solid var(--color-border); border-radius:var(--radius-sm); padding:8px 10px; color:var(--color-text-main); font-size:0.82rem; resize:vertical; font-family:inherit;" placeholder="e.g. Simulates internal Confluence. Alert SOC immediately if flag.hit fires.">' + escapeHtml(n.notes || '') + '</textarea>' +
            '</div>' +
            '<button class="btn btn-primary" id="btn-save-node-meta" onclick="saveNodeMetadata(\\'' + sid + '\\')">' +
              '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>' +
              'Save Details & Notes' +
            '</button>' +
          '</div>';
        const exposedPort = Number.isInteger(Number(n.honeypot_port)) ? Number(n.honeypot_port) : '';
        const canConfigure = caps.includes('control.configure_honeypot');
        const currentProfile = ['all', 'http', 'wiki', 'openapi', 'mcp'].includes(n.service_profile) ? n.service_profile : 'all';
        const profileOptions = [
          ['all', __loc.t('profile_all')],
          ['http', __loc.t('profile_http')],
          ['wiki', __loc.t('profile_wiki')],
          ['openapi', __loc.t('profile_openapi')],
          ['mcp', __loc.t('profile_mcp')],
        ].map(([value, label]) => '<option value="' + value + '"' + (value === currentProfile ? ' selected' : '') + '>' + escapeHtml(label) + '</option>').join('');
        const compatibleTemplates = (state.templates || []).filter((t) =>
          t.profile === 'all' || currentProfile === 'all' || t.profile === currentProfile
        );
        const templateOptions = compatibleTemplates.map((t) => {
          const value = t.id + '|' + t.version;
          const selected = t.id === n.template_id && Number(t.version) === Number(n.template_version);
          return '<option value="' + escapeHtml(value) + '"' + (selected ? ' selected' : '') + '>' + escapeHtml(t.name + ' · v' + t.version + ' · ' + t.profile) + '</option>';
        }).join('');
        const canApplyTemplate = caps.includes('control.apply_template') && compatibleTemplates.length > 0;
        const config = canConfigure
          ? '<div class="panel">' +
              '<p class="panel-sub" style="margin-bottom:14px;">Change the public listener and the deceptive service presented to attackers. The Control API stays on port ' + escapeHtml(n.port) + '.</p>' +
              '<div class="form-row">' +
                '<div class="form-group"><label for="node-config-port">' + escapeHtml(__loc.t('label_exposed_port')) + '</label><input id="node-config-port" type="number" min="1" max="65535" value="' + escapeHtml(exposedPort) + '"></div>' +
                '<div class="form-group"><label for="node-config-profile">' + escapeHtml(__loc.t('label_simulates')) + '</label><select id="node-config-profile">' + profileOptions + '</select></div>' +
              '</div>' +
              '<button class="btn btn-primary" id="btn-save-node-config" onclick="configureNode(\\'' + sid + '\\')">' + escapeHtml(__loc.t('btn_apply_honeypot_config')) + '</button>' +
              '<p class="panel-sub" style="margin-top:12px;">If Docker publishes a fixed host port, redeploy that mapping after changing the exposed port.</p>' +
            '</div>'
          : '<div class="panel"><p class="panel-sub">This node does not advertise remote public-port/profile configuration support. Upgrade the honeypot deployment to enable it.</p></div>';
        const templateConfig = canApplyTemplate
          ? '<div class="panel">' +
              '<p class="panel-sub" style="margin-bottom:14px;">Deploy a versioned, sanitized content template. The template changes the public pages without executing code on the node.</p>' +
              '<div class="form-row"><div class="form-group"><label for="node-config-template">' + escapeHtml(__loc.t('label_template')) + '</label><select id="node-config-template">' + templateOptions + '</select></div></div>' +
              '<button class="btn btn-primary" id="btn-apply-node-template" onclick="applyNodeTemplate(\\'' + sid + '\\')">' + escapeHtml(__loc.t('btn_apply_template')) + '</button>' +
              '<p class="panel-sub" style="margin-top:12px;">Templates are versioned so the previous content can be restored.</p>' +
            '</div>'
          : '<div class="panel"><p class="panel-sub">No compatible templates are available, or this node does not advertise template support.</p></div>';
        const ops = '<div class="panel">' +
            '<div style="display:flex; flex-direction:column; gap:10px;">' +
              '<button class="btn btn-secondary" style="justify-content:flex-start;" onclick="executeNodeCommand(\\'' + sid + '\\', \\'restart\\')">Restart</button>' +
              '<button class="btn btn-secondary" style="justify-content:flex-start;" onclick="executeNodeCommand(\\'' + sid + '\\', \\'rotate_challenges\\')">Rotate challenges</button>' +
              '<button class="btn btn-danger" style="justify-content:flex-start;" onclick="unenrollNode(\\'' + sid + '\\')">' + escapeHtml(__loc.t('btn_unenroll')) + '</button>' +
            '</div>' +
            '<p class="panel-sub" style="margin-top:12px;">No operations yet</p>' +
          '</div>';
        const eventsForNode = (state.events || []).filter((e) => e.site_id === n.site_id).slice(0, 20);
        const activity = eventsForNode.length
          ? '<div class="panel">' + eventsForNode.map((e) => '<div class="mono" style="font-size:0.75rem;padding:6px 0;">' + escapeHtml(e.type) + ' · ' + escapeHtml(timeAgo(e.ts)) + '</div>').join('') + '</div>'
          : '<div class="empty-box"><div class="empty-title">' + escapeHtml(__loc.t('empty_events_title')) + '</div></div>';
        els.drawerContent.innerHTML =
          '<div class="drawer-tabs" role="tablist">' +
            '<button type="button" role="tab" aria-selected="true" data-drawer-tab="summary">' + escapeHtml(__loc.t('drawer_tab_summary')) + '</button>' +
            '<button type="button" role="tab" aria-selected="false" data-drawer-tab="activity">' + escapeHtml(__loc.t('drawer_tab_activity')) + '</button>' +
            '<button type="button" role="tab" aria-selected="false" data-drawer-tab="config">' + escapeHtml(__loc.t('drawer_tab_config')) + '</button>' +
            '<button type="button" role="tab" aria-selected="false" data-drawer-tab="ops">' + escapeHtml(__loc.t('drawer_tab_ops')) + '</button>' +
          '</div>' +
          '<div data-drawer-panel="summary">' + summary + nodeMetaSection + '</div>' +
          '<div data-drawer-panel="activity" hidden>' + activity + '</div>' +
          '<div data-drawer-panel="config" hidden>' + config + templateConfig + '</div>' +
          '<div data-drawer-panel="ops" hidden>' + ops + '</div>';
        els.drawerContent.querySelectorAll('[data-drawer-tab]').forEach((btn) => {
          btn.addEventListener('click', () => {
            const tab = btn.getAttribute('data-drawer-tab');
            els.drawerContent.querySelectorAll('[data-drawer-tab]').forEach((b) => b.setAttribute('aria-selected', b === btn ? 'true' : 'false'));
            els.drawerContent.querySelectorAll('[data-drawer-panel]').forEach((p) => { p.hidden = p.getAttribute('data-drawer-panel') !== tab; });
          });
        });
      };

      function closeDrawer(updateUrl = true) {
        els.drawerOverlay.classList.remove('active');
        els.nodeDrawer.classList.remove('active');
        if (updateUrl && window.location.pathname.startsWith('/nodes/')) {
          window.history.pushState({ tab: 'honeypots' }, 'Honeypots | vAIvar Central Command', '/honeypots');
          document.title = 'Honeypots | vAIvar Central Command';
        }
      }

      document.getElementById('btn-close-drawer')?.addEventListener('click', closeDrawer);
      els.drawerOverlay?.addEventListener('click', closeDrawer);

      function enrollFields() {
        return {
          host: document.getElementById('enroll-host').value.trim(),
          port: Number(document.getElementById('enroll-port').value),
          channel: document.getElementById('enroll-channel').value,
          token: document.getElementById('enroll-token').value.trim(),
        };
      }

      function setEnrollStep(step) {
        const s1 = document.getElementById('enroll-step-1');
        const s2 = document.getElementById('enroll-step-2');
        const testBtn = document.getElementById('btn-test-connection');
        const addBtn = document.getElementById('btn-submit-enroll');
        const backBtn = document.getElementById('btn-enroll-back');
        if (s1) s1.hidden = step !== 1;
        if (s2) s2.hidden = step !== 2;
        if (testBtn) testBtn.hidden = step !== 1;
        if (addBtn) addBtn.hidden = step !== 2;
        if (backBtn) backBtn.hidden = step !== 2;
      }

      function openEnrollModal() {
        const errEl = document.getElementById('enroll-error');
        if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
        const tok = document.getElementById('enroll-token');
        if (tok) tok.value = '';
        const channel = document.getElementById('enroll-channel');
        if (channel) channel.value = 'encrypted';
        const commandWrap = document.getElementById('bootstrap-command-wrap');
        if (commandWrap) commandWrap.hidden = true;
        const command = document.getElementById('bootstrap-command');
        if (command) command.value = '';
        state.enrollPreview = null;
        setEnrollStep(1);
        els.modalEnroll.classList.add('active');
        document.getElementById('enroll-host')?.focus();
      }
      window.openEnrollModal = openEnrollModal;
      function closeEnrollModal() {
        els.modalEnroll.classList.remove('active');
        const tok = document.getElementById('enroll-token');
        if (tok) tok.value = '';
        state.enrollPreview = null;
        setEnrollStep(1);
      }

      document.getElementById('link-enroll-hero')?.addEventListener('click', openEnrollModal);
      document.getElementById('btn-enroll-page')?.addEventListener('click', openEnrollModal);
      document.getElementById('btn-close-enroll')?.addEventListener('click', closeEnrollModal);
      document.getElementById('btn-cancel-enroll')?.addEventListener('click', closeEnrollModal);
      document.getElementById('btn-enroll-back')?.addEventListener('click', () => { state.enrollPreview = null; setEnrollStep(1); });

      document.getElementById('btn-toggle-token-vis')?.addEventListener('click', () => {
        const inp = document.getElementById('enroll-token');
        const show = inp.type === 'password';
        inp.type = show ? 'text' : 'password';
        document.getElementById('btn-toggle-token-vis')?.setAttribute('aria-label', show ? 'Hide barrier token' : 'Show barrier token');
      });

      const shellQuote = function(value) {
        return "'" + String(value).replace(/'/g, "'\\''") + "'";
      };

      document.getElementById('btn-prepare-bootstrap')?.addEventListener('click', async () => {
        const host = document.getElementById('enroll-host').value.trim();
        const controlPort = Number(document.getElementById('enroll-port').value);
        const publicPort = Number(document.getElementById('enroll-public-port').value);
        const profile = document.getElementById('enroll-profile').value;
        const installDir = document.getElementById('enroll-install-dir').value.trim();
        const projectName = document.getElementById('enroll-project-name').value.trim();
        const siteId = document.getElementById('enroll-site-id').value.trim();
        const statusEl = document.getElementById('enroll-error');
        const validInstallDir = installDir.startsWith('/') && installDir !== '/' &&
          !installDir.includes('/../') && !installDir.endsWith('/..') && !installDir.includes('/./') && !installDir.endsWith('/.') &&
          !new RegExp('[^A-Za-z0-9._/-]').test(installDir);
        if (!host || !Number.isInteger(controlPort) || controlPort < 1 || controlPort > 65535 ||
          !Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535 || controlPort === publicPort ||
          !validInstallDir || !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(projectName) ||
          !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(siteId)) {
          statusEl.textContent = 'Use a host, two different valid ports, an install directory, a valid Compose project name, and a site ID.';
          statusEl.style.display = 'block';
          return;
        }
        const btn = document.getElementById('btn-prepare-bootstrap');
        btn.disabled = true;
        const response = await apiFetch('/bootstrap/tokens', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ttl_seconds: 900, metadata: { host, control_port: controlPort, honeypot_port: publicPort, profile, install_dir: installDir, compose_project: projectName, site_id: siteId } }),
        });
        btn.disabled = false;
        if (!response.ok || !response.body?.bootstrap_token) {
          statusEl.textContent = response.body?.error || 'Only an administrator can generate a bootstrap command.';
          statusEl.style.display = 'block';
          return;
        }
        const token = response.body.bootstrap_token;
        const central = window.location.origin;
        const command = 'curl -fsSL -H ' + shellQuote('X-Vaivar-Bootstrap-Token: ' + token) + ' ' + shellQuote(central + '/api/v1/bootstrap/installer') +
          ' | sudo bash -s -- --central ' + shellQuote(central) + ' --bootstrap-token ' + shellQuote(token) +
          ' --host ' + shellQuote(host) + ' --api-port ' + controlPort + ' --public-port ' + publicPort + ' --profile ' + shellQuote(profile) + ' --control-channel encrypted' +
          ' --install-dir ' + shellQuote(installDir) + ' --project-name ' + shellQuote(projectName) + ' --site-id ' + shellQuote(siteId);
        const commandEl = document.getElementById('bootstrap-command');
        const commandWrap = document.getElementById('bootstrap-command-wrap');
        commandEl.value = command;
        commandWrap.hidden = false;
        statusEl.style.display = 'none';
      });

      document.getElementById('btn-copy-bootstrap')?.addEventListener('click', () => {
        const command = document.getElementById('bootstrap-command')?.value || '';
        if (command) copyToClipboard(command, 'Deploy command');
      });

      document.getElementById('btn-test-connection')?.addEventListener('click', async () => {
        const { host, port, channel, token } = enrollFields();
        const errEl = document.getElementById('enroll-error');
        errEl.style.display = 'none';
        if (!host || !port || port < 1 || port > 65535 || token.length < 16 ||
          (channel !== 'encrypted' && channel !== 'legacy')) {
          errEl.textContent = 'Host, control API port (1–65535), a valid control channel, and barrier token (≥16 chars) are required.';
          errEl.style.display = 'block';
          return;
        }
        const registrationBody = {
          host, port, token, tls: 'http', channel,
        };
        const btn = document.getElementById('btn-test-connection');
        btn.disabled = true;
        let res = await apiFetch('/nodes/preview', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(registrationBody),
        });
        if (res.status === 404 || res.status === 405) {
          res = await apiFetch('/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(registrationBody),
          });
          btn.disabled = false;
          if (res.ok) {
            showToast(__loc.t('toast_honeypot_added'), 'success');
            closeEnrollModal();
            fetchAll();
            setTab('honeypots');
            return;
          }
          if (res.status === 409 && res.body?.existing_site_id) {
            errEl.innerHTML = escapeHtml(__loc.t('enroll_duplicate')) + ' <button class="btn btn-outline btn-sm" type="button" id="enroll-open-existing">' + escapeHtml(__loc.t('enroll_open_existing')) + '</button>';
            errEl.style.display = 'block';
            document.getElementById('enroll-open-existing')?.addEventListener('click', () => {
              closeEnrollModal();
              openNodeDrawer(res.body.existing_site_id);
            });
            return;
          }
          errEl.textContent = res.body?.error || 'Could not verify this honeypot.';
          errEl.style.display = 'block';
          return;
        }
        btn.disabled = false;
        if (!res.ok) {
          if (res.status === 409 && res.body?.existing_site_id) {
            errEl.innerHTML = escapeHtml(__loc.t('enroll_duplicate')) + ' <button class="btn btn-outline btn-sm" type="button" id="enroll-open-existing">' + escapeHtml(__loc.t('enroll_open_existing')) + '</button>';
            errEl.style.display = 'block';
            document.getElementById('enroll-open-existing')?.addEventListener('click', () => {
              closeEnrollModal();
              openNodeDrawer(res.body.existing_site_id);
            });
            return;
          }
          errEl.textContent = res.body?.error || 'Could not verify this honeypot.';
          errEl.style.display = 'block';
          return;
        }
        if (res.body?.duplicate && res.body.existing_site_id) {
          errEl.innerHTML = escapeHtml(__loc.t('enroll_duplicate')) + ' <button class="btn btn-outline btn-sm" type="button" id="enroll-open-existing">' + escapeHtml(__loc.t('enroll_open_existing')) + '</button>';
          errEl.style.display = 'block';
          document.getElementById('enroll-open-existing')?.addEventListener('click', () => {
            closeEnrollModal();
            openNodeDrawer(res.body.existing_site_id);
          });
          return;
        }
        state.enrollPreview = { host, port, channel, token, at: Date.now(), identity: res.body };
        const sum = document.getElementById('enroll-preview-summary');
        if (sum) {
          sum.innerHTML = '<div class="empty-title">' + escapeHtml(host) + ':' + escapeHtml(port) + '</div>' +
            '<div class="empty-desc">site_id ' + escapeHtml(res.body.site_id) + ' · ' + escapeHtml(res.body.api_version || '') + '</div>';
        }
        setEnrollStep(2);
      });

      document.getElementById('btn-submit-enroll')?.addEventListener('click', async () => {
        const errEl = document.getElementById('enroll-error');
        const { host, port, channel, token } = enrollFields();
        const preview = state.enrollPreview;
        if (!preview || Date.now() - preview.at > 60_000 || preview.host !== host || preview.port !== port || preview.token !== token ||
          preview.channel !== channel) {
          errEl.textContent = 'Test connection again before adding.';
          errEl.style.display = 'block';
          setEnrollStep(1);
          return;
        }
        const btn = document.getElementById('btn-submit-enroll');
        btn.disabled = true;
        const { ok, status, body } = await apiFetch('/nodes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            host, port, token, tls: 'http', channel,
          }),
        });
        btn.disabled = false;
        if (ok) {
          showToast(__loc.t('toast_honeypot_added'), 'success');
          closeEnrollModal();
          fetchAll();
          setTab('honeypots');
          return;
        }
        if (status === 409 && body?.existing_site_id) {
          errEl.innerHTML = escapeHtml(__loc.t('enroll_duplicate')) + ' <button class="btn btn-outline btn-sm" type="button" id="enroll-open-existing">' + escapeHtml(__loc.t('enroll_open_existing')) + '</button>';
          errEl.style.display = 'block';
          document.getElementById('enroll-open-existing')?.addEventListener('click', () => {
            closeEnrollModal();
            openNodeDrawer(body.existing_site_id);
          });
          return;
        }
        errEl.textContent = body?.error || 'Could not add this honeypot.';
        errEl.style.display = 'block';
      });

      // Settings
      async function loadSettings() {
        const { ok, body } = await apiFetch('/settings');
        if (ok && body) {
          document.getElementById('input-retention').value = body.retention_days || 90;
        }
      }

      // ── Users & permissions ─────────────────────────────────────────────────
      // Human identities are managed in Keycloak, not here. The Settings →
      // Users panel is informational text rendered directly in the HTML above.
      // No client-side CRUD: role changes happen by editing Keycloak groups.

      document.getElementById('btn-save-settings')?.addEventListener('click', async () => {
        showToast(__loc.t('settings_retention_stub'), 'info');
      });

      // Integration management
      const integrationKinds = [
        { kind: 'cti', label: 'OpenCTI', help: 'STIX 2.1 threat intelligence export' },
        { kind: 'siem', label: 'Splunk HEC', help: 'HTTP Event Collector forwarding' },
        { kind: 'metrics', label: 'Prometheus', help: 'Scrape /metrics endpoint' },
        { kind: 'dashboard', label: 'Grafana', help: 'Dashboard / datasource reference' },
      ];
      const integrationListEl = document.getElementById('integrations-list');
      const integrationModal = document.getElementById('integration-modal');
      const integrationKindSelect = document.getElementById('integration-kind');
      const integrationNameInput = document.getElementById('integration-name');
      const integrationUrlInput = document.getElementById('integration-url');
      const integrationTokenInput = document.getElementById('integration-token');
      const integrationIndexInput = document.getElementById('integration-index');
      const integrationSourceInput = document.getElementById('integration-source');
      const integrationSourcetypeInput = document.getElementById('integration-sourcetype');
      const integrationStatusEl = document.getElementById('integration-status');
      const integrationHelpEl = document.getElementById('integration-help');

      const integrationFormValues = () => {
        const kind = integrationKindSelect ? integrationKindSelect.value : 'cti';
        const url = integrationUrlInput ? integrationUrlInput.value.trim() : '';
        const token = integrationTokenInput ? integrationTokenInput.value.trim() : '';
        const config = { url, token };
        if (kind === 'siem' || kind === 'cti') {
          const index = integrationIndexInput ? integrationIndexInput.value.trim() : '';
          const source = integrationSourceInput ? integrationSourceInput.value.trim() : '';
          const sourcetype = integrationSourcetypeInput ? integrationSourcetypeInput.value.trim() : '';
          if (index) config.index = index;
          if (source) config.source = source;
          if (sourcetype) config.sourcetype = sourcetype;
        }
        return { name: integrationNameInput ? integrationNameInput.value.trim() : '', kind, config_json: JSON.stringify(config) };
      };

      const renderIntegrations = async () => {
        if (!integrationListEl) return;
        const res = await apiFetch('/integrations');
        const integrations = res.body?.integrations;
        integrationListEl.innerHTML = '';
        if (!integrations || !Array.isArray(integrations) || integrations.length === 0) {
          integrationListEl.innerHTML = '<div style="font-size: 0.82rem; color: var(--text-soft); padding: 14px; background: var(--color-surface); border: 1px dashed var(--color-border); border-radius: var(--radius-sm);">No integrations configured yet. Click "Add Integration" to connect OpenCTI, Splunk, Prometheus, or Grafana.</div>';
          return;
        }
        for (const integration of integrations) {
          const card = document.createElement('div');
          card.className = 'integration-card';
          const isEnabled = Boolean(integration.enabled);
          const status = isEnabled ? 'enabled' : 'disabled';
          const label = escapeHtml(integration.label || integration.name);
          const kind = escapeHtml(integration.kind || 'cti');
          const name = escapeHtml(integration.name);
          let safeConfig = '';
          try {
            const parsed = JSON.parse(integration.config_json);
            safeConfig = escapeHtml(parsed.url || integration.config_json);
          } catch {
            safeConfig = escapeHtml(integration.config_json);
          }
          const testedAt = integration.tested_at_ms ? new Date(integration.tested_at_ms).toLocaleString() : 'Not tested yet';
          const enableLabel = isEnabled ? 'Disable' : 'Enable';
          const badgeClass = isEnabled ? 'positive' : 'subtle';
          card.innerHTML =
            '<div class="integration-card-header">' +
              '<div><h4>' + label + '</h4><span class="integration-kind">' + kind.toUpperCase() + ' &bull; ' + name + '</span></div>' +
              '<span class="kpi-badge ' + badgeClass + '">' + status.toUpperCase() + '</span>' +
            '</div>' +
            '<p class="integration-url"><code>' + safeConfig + '</code></p>' +
            '<div class="integration-actions">' +
              '<button class="btn btn-secondary btn-sm integration-action" data-action="test" data-name="' + name + '">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Test' +
              '</button>' +
              '<button class="btn btn-outline btn-sm integration-action" data-action="enable" data-name="' + name + '">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg> ' + enableLabel +
              '</button>' +
              '<button class="btn btn-danger btn-sm integration-action" data-action="delete" data-name="' + name + '">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Delete' +
              '</button>' +
            '</div>' +
            '<div class="integration-meta">Last test: ' + testedAt + (integration.last_error ? ' &bull; <span style="color:var(--color-danger);">' + escapeHtml(integration.last_error) + '</span>' : '') + '</div>';
          integrationListEl.appendChild(card);
        }
        integrationListEl.querySelectorAll('.integration-action').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const action = btn.dataset.action;
            const name = btn.dataset.name;
            if (!action || !name) return;
            if (action === 'test') {
              showToast('Testing integration ' + name + '...', 'info');
              const res = await apiFetch('/integrations/' + encodeURIComponent(name) + '/test', { method: 'POST' });
              const isOk = res.ok && res.body?.ok;
              showToast(isOk ? 'Integration test passed.' : ('Integration test failed: ' + (res.body?.error || 'unreachable')), isOk ? 'success' : 'error');
              await renderIntegrations();
            } else if (action === 'enable') {
              const res = await apiFetch('/integrations/' + encodeURIComponent(name) + '/enable', { method: 'POST' });
              if (res.ok) {
                showToast('Integration ' + (res.body?.enabled ? 'enabled.' : 'disabled.'), 'success');
              } else {
                showToast('Failed to toggle integration.', 'error');
              }
              await renderIntegrations();
            } else if (action === 'delete') {
              if (!confirm('Delete integration "' + name + '"?')) return;
              const res = await apiFetch('/integrations/' + encodeURIComponent(name), { method: 'DELETE' });
              if (res.ok) {
                showToast('Integration deleted.', 'success');
              } else {
                showToast('Failed to delete integration.', 'error');
              }
              await renderIntegrations();
            }
          });
        });
      };

      const openIntegrationModal = () => {
        if (!integrationKindSelect) return;
        integrationKindSelect.innerHTML = integrationKinds.map((k) => '<option value="' + k.kind + '">' + k.label + '</option>').join('');
        integrationKindSelect.value = 'cti';
        if (integrationNameInput) integrationNameInput.value = '';
        if (integrationUrlInput) integrationUrlInput.value = '';
        if (integrationTokenInput) integrationTokenInput.value = '';
        if (integrationIndexInput) integrationIndexInput.value = '';
        if (integrationSourceInput) integrationSourceInput.value = '';
        if (integrationSourcetypeInput) integrationSourcetypeInput.value = '';
        if (integrationHelpEl) integrationHelpEl.textContent = integrationKinds.find((k) => k.kind === 'cti')?.help ?? '';
        if (integrationStatusEl) {
          integrationStatusEl.textContent = '';
          integrationStatusEl.style.display = 'none';
        }
        integrationModal?.classList.add('active');
        integrationModal?.classList.add('open');
      };

      const closeIntegrationModal = () => {
        integrationModal?.classList.remove('active');
        integrationModal?.classList.remove('open');
      };

      integrationKindSelect?.addEventListener('change', () => {
        const kind = integrationKindSelect.value;
        if (integrationNameInput && !integrationNameInput.value) {
          integrationNameInput.value = kind === 'cti' ? 'opencti' : kind;
        }
        if (integrationHelpEl) {
          integrationHelpEl.textContent = integrationKinds.find((k) => k.kind === kind)?.help ?? '';
        }
      });

      document.getElementById('btn-add-integration')?.addEventListener('click', openIntegrationModal);
      document.getElementById('integration-close')?.addEventListener('click', closeIntegrationModal);
      document.getElementById('integration-cancel')?.addEventListener('click', closeIntegrationModal);
      integrationModal?.addEventListener('click', (e) => {
        if (e.target === integrationModal) closeIntegrationModal();
      });

      document.getElementById('integration-save')?.addEventListener('click', async () => {
        const { name, kind, config_json } = integrationFormValues();
        if (integrationStatusEl) {
          integrationStatusEl.textContent = '';
          integrationStatusEl.style.display = 'none';
        }
        if (!name) {
          if (integrationStatusEl) {
            integrationStatusEl.textContent = 'Name is required.';
            integrationStatusEl.style.display = 'block';
          }
          return;
        }
        let parsedConfig = {};
        try { parsedConfig = JSON.parse(config_json); } catch {}
        if (!parsedConfig.url) {
          if (integrationStatusEl) {
            integrationStatusEl.textContent = 'Endpoint URL is required.';
            integrationStatusEl.style.display = 'block';
          }
          return;
        }
        const label = integrationKinds.find((k) => k.kind === kind)?.label ?? kind;
        const res = await apiFetch('/integrations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, kind, label, config_json }),
        });
        if (res.ok) {
          showToast(__loc.t('toast_integration_saved') || 'Integration saved successfully.', 'success');
          closeIntegrationModal();
          await renderIntegrations();
        } else {
          const errMsg = res.body?.error || 'Failed to save integration.';
          if (integrationStatusEl) {
            integrationStatusEl.textContent = errMsg;
            integrationStatusEl.style.display = 'block';
          }
          showToast(errMsg, 'error');
        }
      });

      renderIntegrations();

      document.getElementById('btn-logout')?.addEventListener('click', async () => {
        if (!confirm('Logout from vAIvar Central?')) return;
        // If the session came from Keycloak, end the SSO session too.
        if (state.me && state.me.auth === 'oidc') {
          location.href = '/api/v1/oidc/logout';
          return;
        }
        await apiFetch('/logout', { method: 'POST' });
        location.href = '/login';
      });

      function clearActivityFilters() {
        state.eventFilter = 'all';
        state.searchQuery = '';
        if (els.globalSearch) els.globalSearch.value = '';
        document.querySelectorAll('[data-event-filter]').forEach(b => {
          b.classList.toggle('active', b.dataset.eventFilter === 'all');
        });
        updateFilterIndicator();
        renderActivity();
        setTab('activity', true);
      }

      function updateFilterIndicator() {
        const ind = document.getElementById('activity-active-filter-indicator');
        const txt = document.getElementById('activity-active-filter-text');
        if (!ind || !txt) return;
        const hasFilter = state.eventFilter && state.eventFilter !== 'all';
        const hasSearch = !!state.searchQuery;
        if (hasFilter || hasSearch) {
          ind.style.display = 'inline-flex';
          const labels = [];
          if (hasFilter) {
            const btn = document.querySelector('[data-event-filter="' + state.eventFilter + '"]');
            labels.push(btn ? btn.textContent.trim() : state.eventFilter);
          }
          if (hasSearch) labels.push('Search: "' + state.searchQuery + '"');
          txt.textContent = labels.join(' · ');
        } else {
          ind.style.display = 'none';
        }
      }

      function updateThreatStatusUI() {
        const flags = Number(state.stats?.flags || 0);
        const pill = document.getElementById('threat-status-pill');
        if (pill) {
          if (flags > 0) {
            pill.className = 'threat-status-pill alarm';
            pill.setAttribute('href', '/activity?filter=flag');
            pill.innerHTML = '<span>🚨</span><span>ATTACK DETECTED (' + flags + ' FLAG' + (flags > 1 ? 'S' : '') + ')</span>';
          } else {
            pill.className = 'threat-status-pill normal';
            pill.removeAttribute('href');
            pill.innerHTML = '<span class="pulse-dot"></span><span>MONITORING</span>';
          }
        }

        if (els.badgeEventsCount) {
          if (flags > 0) {
            els.badgeEventsCount.className = 'nav-badge critical-alarm';
            els.badgeEventsCount.textContent = '🚨 ' + flags;
            els.badgeEventsCount.title = flags + ' attack flag(s) captured';
          } else {
            els.badgeEventsCount.className = 'nav-badge';
            els.badgeEventsCount.textContent = formatNumber(state.stats?.events || 0);
            els.badgeEventsCount.title = 'Total events';
          }
        }

        const flagCard = els.statFlags?.closest('.kpi-card');
        if (flagCard) {
          if (flags > 0) {
            flagCard.classList.add('under-attack');
          } else {
            flagCard.classList.remove('under-attack');
          }
        }
      }

      document.querySelectorAll('[data-conn-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
          if (btn.classList.contains('active') && btn.dataset.connFilter !== 'all') {
            document.querySelectorAll('[data-conn-filter]').forEach(b => b.classList.toggle('active', b.dataset.connFilter === 'all'));
            state.connFilter = 'all';
          } else {
            document.querySelectorAll('[data-conn-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.connFilter = btn.dataset.connFilter;
          }
          renderNodes();
          setTab('honeypots', true);
        });
      });

      document.querySelectorAll('[data-proto-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
          if (btn.classList.contains('active') && btn.dataset.protoFilter !== 'all') {
            document.querySelectorAll('[data-proto-filter]').forEach(b => b.classList.toggle('active', b.dataset.protoFilter === 'all'));
            state.protoFilter = 'all';
          } else {
            document.querySelectorAll('[data-proto-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.protoFilter = btn.dataset.protoFilter;
          }
          renderNodes();
          setTab('honeypots', true);
        });
      });

      document.querySelectorAll('[data-event-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetFilter = btn.dataset.eventFilter;
          // Toggle off if clicking the already active non-all filter
          if (btn.classList.contains('active') && targetFilter !== 'all') {
            clearActivityFilters();
            return;
          }
          if (targetFilter === 'all') {
            clearActivityFilters();
            return;
          }
          document.querySelectorAll('[data-event-filter]').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          state.eventFilter = targetFilter;
          updateFilterIndicator();
          renderActivity();
          setTab('activity', true);
        });
      });

      document.getElementById('btn-clear-activity-filter')?.addEventListener('click', clearActivityFilters);

      document.getElementById('threat-status-pill')?.addEventListener('click', (e) => {
        if (state.stats?.flags > 0) {
          e.preventDefault();
          state.eventFilter = 'flag';
          updateFilterIndicator();
          renderActivity();
          setTab('activity', true);
        }
      });

      document.getElementById('mode-events')?.addEventListener('click', () => {
        state.activityMode = 'events';
        applyActivityMode();
        setTab('activity', true);
      });
      document.getElementById('mode-sessions')?.addEventListener('click', () => {
        state.activityMode = 'sessions';
        applyActivityMode();
        setTab('activity', true);
      });

      document.querySelectorAll('[data-settings-section]').forEach((a) => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          state.settingsSection = a.dataset.settingsSection;
          document.querySelectorAll('[data-settings-section]').forEach((x) => x.classList.toggle('active', x === a));
          const target = document.getElementById('settings-' + state.settingsSection);
          target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          setTab('settings', true);
        });
      });

      document.querySelectorAll('a.kpi-link').forEach((a) => {
        a.addEventListener('click', (e) => {
          if (e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) return;
          e.preventDefault();
          const href = a.getAttribute('href') || '';
          if (href.includes('mode=sessions')) state.activityMode = 'sessions';
          if (href.includes('filter=flag')) {
            state.eventFilter = 'flag';
            document.querySelectorAll('[data-event-filter]').forEach(b => b.classList.toggle('active', b.dataset.eventFilter === 'flag'));
          }
          setTab(a.dataset.tab || 'overview', true);
        });
      });

      function closeSearchOverlay() {
        const ov = document.getElementById('search-overlay');
        if (ov) { ov.classList.remove('open'); ov.hidden = true; }
        els.globalSearch?.setAttribute('aria-expanded', 'false');
      }

      function renderSearchOverlay() {
        const ov = document.getElementById('search-overlay');
        if (!ov) return;
        const q = (els.globalSearch?.value || '').trim().toLowerCase();
        const hits = [];
        const pages = [
          { tab: 'overview', label: __loc.t('nav_overview') },
          { tab: 'honeypots', label: __loc.t('nav_honeypots') },
          { tab: 'activity', label: __loc.t('nav_activity') },
          { tab: 'settings', label: __loc.t('nav_settings') },
        ].filter((p) => !q || p.label.toLowerCase().includes(q));
        hits.push({ group: __loc.t('search_pages'), items: pages.map((p) => ({ kind: 'page', tab: p.tab, label: p.label })) });
        if (q) {
          const nodes = state.nodes.filter((n) =>
            (n.host || '').toLowerCase().includes(q) || String(n.port).includes(q) || String(n.honeypot_port || '').includes(q) ||
            (n.service_profile || '').toLowerCase().includes(q) || (n.site_id || '').toLowerCase().includes(q)
          ).slice(0, 5);
          hits.push({ group: __loc.t('nav_honeypots'), items: nodes.map((n) => ({ kind: 'node', id: n.site_id, label: n.host + ':' + n.port + ' · public ' + (n.honeypot_port || '?') })) });
          const events = state.events.filter((e) =>
            (e.type || '').toLowerCase().includes(q) || (e.site_id || '').toLowerCase().includes(q) || (e.session_id || '').toLowerCase().includes(q)
          ).slice(0, 5);
          hits.push({ group: __loc.t('activity_mode_events'), items: events.map((e) => ({ kind: 'event', id: e.session_id, label: (e.type || 'event') + ' · ' + (e.site_id || '') })) });
        }
        const groups = hits.filter((g) => g.items.length);
        if (!groups.length) {
          ov.innerHTML = '<div class="search-group-title">' + escapeHtml((__loc.t('search_no_results') || '').replace('{q}', q)) + '</div>';
        } else {
          ov.innerHTML = groups.map((g) =>
            '<div class="search-group-title">' + escapeHtml(g.group) + '</div>' +
            g.items.map((item) => '<button type="button" class="search-hit" role="option" data-kind="' + item.kind + '" data-tab="' + (item.tab || '') + '" data-id="' + escapeHtml(item.id || '') + '">' + escapeHtml(item.label) + '</button>').join('')
          ).join('');
        }
        ov.hidden = false;
        ov.classList.add('open');
        els.globalSearch?.setAttribute('aria-expanded', 'true');
        ov.querySelectorAll('.search-hit').forEach((btn) => {
          btn.addEventListener('click', () => {
            const kind = btn.dataset.kind;
            if (kind === 'page') setTab(btn.dataset.tab, true);
            else if (kind === 'node' && btn.dataset.id) { setTab('honeypots', true); openNodeDrawer(btn.dataset.id); }
            else if (kind === 'event') { state.searchQuery = btn.dataset.id || q; setTab('activity', true); renderActivity(); }
            closeSearchOverlay();
          });
        });
      }

      els.globalSearch?.addEventListener('input', () => {
        state.searchQuery = (els.globalSearch.value || '').trim();
        updateFilterIndicator();
        renderSearchOverlay();
        if (state.activeTab === 'honeypots') renderNodes();
        if (state.activeTab === 'activity') renderActivity();
      });
      els.globalSearch?.addEventListener('focus', () => renderSearchOverlay());
      els.globalSearch?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const first = document.querySelector('#search-overlay .search-hit');
          if (first) first.click();
          else {
            state.searchQuery = (els.globalSearch.value || '').trim();
            if (state.activeTab === 'honeypots' || state.activeTab === 'activity') setTab(state.activeTab, true);
            closeSearchOverlay();
          }
        }
        if (e.key === 'Escape') closeSearchOverlay();
      });
      document.addEventListener('click', (e) => {
        if (!e.target.closest('.search-box')) closeSearchOverlay();
        if (!e.target.closest('.card-overflow')) document.querySelectorAll('.overflow-menu.open').forEach((m) => m.classList.remove('open'));
      });

      window.addEventListener('keydown', (e) => {
        const tag = document.activeElement?.tagName?.toLowerCase();
        const isEditable = tag === 'input' || tag === 'textarea' || tag === 'select' || document.activeElement?.isContentEditable;
        if (e.key === '/' && !isEditable) {
          e.preventDefault();
          els.globalSearch?.focus();
        }
        if (e.key === 'Escape') {
          closeDrawer();
          closeEnrollModal();
          closeIntegrationModal();
          closeSearchOverlay();
          document.querySelectorAll('.overflow-menu.open').forEach((m) => m.classList.remove('open'));
          appShell?.classList.remove('nav-open');
        }
      });

      // Export JSON
      document.getElementById('btn-export-events')?.addEventListener('click', () => {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(state.events, null, 2));
        const a = document.createElement('a');
        a.setAttribute('href', dataStr);
        a.setAttribute('download', 'vaivar-threat-events-' + Date.now() + '.json');
        document.body.appendChild(a);
        a.click();
        a.remove();
        showToast('Exported threat log to JSON.', 'success');
      });

      // Sidebar Collapse & Expand
      const appShell = document.querySelector('.app-shell');
      const btnToggleSidebar = document.getElementById('btn-toggle-sidebar');

      try {
        if (localStorage.getItem('vaivar-sidebar-collapsed') === 'true') {
          appShell?.classList.add('sidebar-collapsed');
        }
        document.documentElement.classList.remove('preload-sidebar-collapsed');
      } catch (e) {}

      function toggleSidebar() {
        if (!appShell) return;
        if (window.matchMedia('(max-width: 859px)').matches) {
          const open = appShell.classList.toggle('nav-open');
          btnToggleSidebar?.setAttribute('aria-expanded', open ? 'true' : 'false');
          return;
        }
        const isCollapsed = appShell.classList.toggle('sidebar-collapsed');
        btnToggleSidebar?.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
        try {
          localStorage.setItem('vaivar-sidebar-collapsed', isCollapsed ? 'true' : 'false');
        } catch (e) {}
        setTimeout(() => {
          if (state.activeTab === 'overview') {
            renderThreatChart();
          }
        }, 260);
      }

      btnToggleSidebar?.addEventListener('click', toggleSidebar);
      document.getElementById('nav-backdrop')?.addEventListener('click', () => {
        appShell?.classList.remove('nav-open');
        btnToggleSidebar?.setAttribute('aria-expanded', 'false');
      });

      // Auto-Sync (Configured via Settings)
      function resetSyncTimer() {
        if (state.syncTimer) clearInterval(state.syncTimer);
        const rate = Number(els.syncRate ? els.syncRate.value : 15000);
        if (rate > 0) {
          state.syncTimer = setInterval(fetchAll, rate);
        }
      }

      try {
        const savedSyncRate = localStorage.getItem('vaivar-sync-rate');
        if (savedSyncRate && els.syncRate) {
          els.syncRate.value = savedSyncRate;
        }
      } catch (e) {}

      els.syncRate?.addEventListener('change', () => {
        try { localStorage.setItem('vaivar-sync-rate', els.syncRate.value); } catch (e) {}
        resetSyncTimer();
        showToast('Sync interval updated.', 'info');
      });
      els.btnManualRefresh?.addEventListener('click', fetchAll);

      // Theme Management
      function updateThemeUI(theme) {
        const toggle = document.getElementById('btn-theme-toggle');
        const isDark = theme === 'dark';
        if (toggle) {
          toggle.setAttribute('aria-checked', isDark ? 'true' : 'false');
          toggle.title = isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode';
        }
      }

      function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        try { localStorage.setItem('vaivar-theme', theme); } catch (e) {}
        updateThemeUI(theme);
        if (state.activeTab === 'overview') {
          renderThreatChart();
        }
      }

      const activeTheme = document.documentElement.getAttribute('data-theme') || 'light';
      updateThemeUI(activeTheme);

      document.getElementById('btn-theme-toggle')?.addEventListener('click', () => {
        const curr = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
        const next = curr === 'dark' ? 'light' : 'dark';
        setTheme(next);
        showToast('Switched to ' + next + ' theme', 'info');
      });

      // Language selector: Select -> Apply (preview) -> Save (persist) / Revert (restore)
      const settingLanguage = document.getElementById('setting-language');
      const btnApplyLanguage = document.getElementById('btn-apply-language');
      const btnSaveLanguage = document.getElementById('btn-save-language');
      const btnRevertLanguage = document.getElementById('btn-revert-language');

      let savedLocale = localStorage.getItem('vaivar-locale') || 'eng';

      function updateLanguageRevertButton() {
        const currentActive = __loc.getLocale ? __loc.getLocale() : savedLocale;
        if (btnRevertLanguage) {
          btnRevertLanguage.style.display = (currentActive !== savedLocale) ? 'inline-flex' : 'none';
        }
      }

      btnApplyLanguage?.addEventListener('click', () => {
        const selected = settingLanguage ? settingLanguage.value : savedLocale;
        __loc.setLocale(selected, false); // PREVIEW ONLY (does not write to localStorage)
        updateLanguageRevertButton();
        showToast(__loc.t('toast_language_applied') || 'Language preview applied. Click Save to keep, or Revert to restore.', 'info');
      });

      btnSaveLanguage?.addEventListener('click', () => {
        const selected = settingLanguage ? settingLanguage.value : savedLocale;
        savedLocale = selected;
        __loc.saveLocale(selected); // PERSISTS to localStorage and applies
        updateLanguageRevertButton();
        showToast(__loc.t('toast_language_saved') || 'Language saved successfully.', 'success');
      });

      btnRevertLanguage?.addEventListener('click', () => {
        if (settingLanguage) settingLanguage.value = savedLocale;
        __loc.setLocale(savedLocale, false);
        updateLanguageRevertButton();
        showToast(__loc.t('toast_language_reverted') || 'Language restored to saved preference.', 'info');
      });

      // Reflect stored locale in the selector on load.
      if (settingLanguage) settingLanguage.value = savedLocale;
      updateLanguageRevertButton();
      __loc.applyTranslations();
      handleRoute();
      fetchAll();
      resetSyncTimer();
    })();
  </script>
</body>
</html>`;
};
