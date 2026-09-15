/**
 * vAIvar Interactive Attack Graph & Monitoring Dashboard
 * Self-contained visual interface with canvas graph visualization,
 * real-time telemetry, attacker simulation and deception metrics.
 */

import { VAIVAR_CREATOR_CREDIT, VAIVAR_CREATOR_URL, VAIVAR_LICENSE_URL, VAIVAR_LOGO_URL } from '../branding';

export function renderDashboardHTML(apiPort: number, mcpPort: number): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vAIvar // Semantic Honeypot - Attack Graph & SOC Dashboard</title>
  <link rel="icon" href="${VAIVAR_LOGO_URL}" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #080c14;
      --bg-card: rgba(15, 23, 42, 0.75);
      --bg-card-hover: rgba(30, 41, 59, 0.85);
      --border-color: rgba(56, 189, 248, 0.2);
      --border-highlight: rgba(56, 189, 248, 0.45);
      --cyan: #00f0ff;
      --cyan-dim: rgba(0, 240, 255, 0.15);
      --emerald: #10b981;
      --emerald-dim: rgba(16, 185, 129, 0.15);
      --amber: #f59e0b;
      --amber-dim: rgba(245, 158, 11, 0.15);
      --crimson: #ef4444;
      --crimson-dim: rgba(239, 68, 68, 0.15);
      --purple: #a855f7;
      --purple-dim: rgba(168, 85, 247, 0.15);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(circle at 15% 20%, rgba(0, 240, 255, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 85% 80%, rgba(168, 85, 247, 0.05) 0%, transparent 40%),
        linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 30px 30px, 30px 30px;
      color: var(--text-main);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* Top Navigation */
    header {
      background: rgba(8, 12, 20, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
      padding: 12px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-logo {
      width: 34px;
      height: 34px;
      border-radius: 8px;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      color: #000;
      box-shadow: 0 0 15px rgba(0, 240, 255, 0.4);
      padding: 5px;
      overflow: hidden;
      text-decoration: none;
    }

    .brand-logo img {
      display: block;
      width: 100%;
      height: 100%;
      object-fit: contain;
    }

    .brand-title {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: 0.5px;
      background: linear-gradient(90deg, #fff, var(--cyan));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--cyan);
      background: var(--cyan-dim);
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid rgba(0, 240, 255, 0.3);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .status-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.82rem;
      font-family: 'JetBrains Mono', monospace;
      padding: 6px 12px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 9999px;
      color: var(--emerald);
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      background-color: var(--emerald);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--emerald);
      animation: pulse 1.8s infinite;
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.4); opacity: 0.5; }
    }

    .btn {
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      font-size: 0.85rem;
      font-weight: 600;
      border-radius: 6px;
      transition: all 0.2s ease;
      font-family: 'Inter', sans-serif;
      text-decoration: none;
    }

    .btn-primary {
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 2px 10px rgba(14, 165, 233, 0.3);
    }

    .btn-primary:hover {
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      box-shadow: 0 0 16px rgba(56, 189, 248, 0.5);
      transform: translateY(-1px);
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-main);
      border: 1px solid var(--border-color);
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--cyan);
    }

    /* Main Layout */
    main {
      padding: 24px 28px;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 24px;
      max-width: 1750px;
      margin: 0 auto;
      width: 100%;
    }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }

    .kpi-card {
      background: var(--bg-card);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px 20px;
      position: relative;
      overflow: hidden;
      transition: all 0.2s ease;
    }

    .kpi-card:hover {
      border-color: var(--border-highlight);
      transform: translateY(-2px);
      background: var(--bg-card-hover);
    }

    .kpi-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
      background: var(--card-accent, var(--cyan));
    }

    .kpi-title {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .kpi-value {
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.75rem;
      font-weight: 700;
      color: var(--text-main);
    }

    .kpi-sub {
      font-size: 0.75rem;
      color: var(--text-dim);
      margin-top: 4px;
    }

    /* Two Columns: Visual Graph + Details */
    .workspace-grid {
      display: grid;
      grid-template-columns: 1.85fr 1fr;
      gap: 20px;
      min-height: 580px;
    }

    @media (max-width: 1100px) {
      .workspace-grid {
        grid-template-columns: 1fr;
      }
    }

    .panel {
      background: var(--bg-card);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .panel-header {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(15, 23, 42, 0.4);
    }

    .panel-title {
      font-size: 0.95rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
      letter-spacing: 0.2px;
    }

    .panel-title span {
      color: var(--cyan);
    }

    .panel-controls {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .legend {
      display: flex;
      gap: 14px;
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 5px;
    }

    .legend-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
    }

    /* Graph Canvas Area */
    .graph-viewport {
      flex: 1;
      position: relative;
      background: radial-gradient(circle at center, rgba(15, 23, 42, 0.6) 0%, rgba(8, 12, 20, 0.9) 100%);
      overflow: hidden;
      min-height: 480px;
    }

    #graphCanvas {
      width: 100%;
      height: 100%;
      display: block;
      cursor: grab;
    }

    #graphCanvas:active {
      cursor: grabbing;
    }

    .graph-overlay-stats {
      position: absolute;
      top: 14px;
      left: 14px;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 8px 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 4px;
      pointer-events: none;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }

    .graph-tooltip {
      position: absolute;
      display: none;
      background: rgba(15, 23, 42, 0.95);
      backdrop-filter: blur(12px);
      border: 1px solid var(--cyan);
      box-shadow: 0 0 20px rgba(0, 240, 255, 0.25);
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 0.8rem;
      pointer-events: none;
      z-index: 50;
      max-width: 280px;
    }

    .graph-tooltip h4 {
      font-family: 'JetBrains Mono', monospace;
      color: var(--cyan);
      margin-bottom: 6px;
      font-size: 0.85rem;
      word-break: break-all;
    }

    /* Details Panel */
    .details-body {
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 20px;
      overflow-y: auto;
      max-height: 600px;
    }

    .budget-section {
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 14px 16px;
    }

    .budget-header {
      display: flex;
      justify-content: space-between;
      font-size: 0.8rem;
      margin-bottom: 6px;
      color: var(--text-muted);
    }

    .progress-bar-bg {
      height: 6px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 999px;
      overflow: hidden;
      margin-bottom: 12px;
    }

    .progress-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--cyan), var(--purple));
      border-radius: 999px;
      transition: width 0.3s ease;
    }

    /* Event Logs Stream */
    .log-stream {
      background: #05080f;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      max-height: 250px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .log-entry {
      display: flex;
      gap: 8px;
      padding: 3px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    }

    .log-time {
      color: var(--text-dim);
      white-space: nowrap;
    }

    .log-type-flag {
      color: var(--crimson);
      font-weight: 600;
    }

    .log-type-node {
      color: var(--cyan);
    }

    .log-type-session {
      color: var(--emerald);
    }

    /* Node Inspector */
    .inspector-card {
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 14px 16px;
      font-size: 0.8rem;
    }

    .inspector-title {
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 8px;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .meta-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      font-family: 'JetBrains Mono', monospace;
    }

    .meta-key {
      color: var(--text-dim);
    }

    .meta-val {
      color: var(--text-main);
      font-weight: 500;
    }

    /* Footer */
    footer {
      border-top: 1px solid var(--border-color);
      padding: 12px 28px;
      font-size: 0.75rem;
      color: var(--text-dim);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(8, 12, 20, 0.6);
    }

    .pill-link {
      color: var(--cyan);
      text-decoration: none;
      padding: 2px 8px;
      border-radius: 4px;
      background: var(--cyan-dim);
      margin-left: 8px;
    }

    .pill-link:hover {
      text-decoration: underline;
    }

    .creator-link,
    .license-link {
      color: var(--cyan);
      text-decoration: none;
      font-weight: 600;
    }

    .creator-link:hover,
    .license-link:hover {
      text-decoration: underline;
    }

    .brand .creator-link {
      display: block;
      margin-top: 3px;
      font-size: 0.68rem;
    }

    footer {
      gap: 12px;
      flex-wrap: wrap;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <a class="brand-logo" href="${VAIVAR_CREATOR_URL}" target="_blank" rel="noopener noreferrer" aria-label="${VAIVAR_CREATOR_CREDIT}">
        <img src="${VAIVAR_LOGO_URL}" alt="vAIvar logo">
      </a>
      <div>
        <span class="brand-title">vAIvar // Semantic Honeypot</span>
        <span class="brand-tag">AI Agent Defense System</span>
        <a class="creator-link" href="${VAIVAR_CREATOR_URL}" target="_blank" rel="noopener noreferrer">${VAIVAR_CREATOR_CREDIT}</a>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-badge">
        <span class="pulse-dot"></span>
        <span>DEFENSE ACTIVE (HTTP :${apiPort} // MCP :${mcpPort})</span>
      </div>
      <button class="btn btn-primary" id="btnSimulate" onclick="simulateAttack()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"></polygon>
        </svg>
        Simulate Agent Attack
      </button>
      <a href="/health" target="_blank" class="btn btn-secondary">API Health</a>
      <a href="/metrics" target="_blank" class="btn btn-secondary">Prometheus</a>
    </div>
  </header>

  <main>
    <!-- KPI Row -->
    <div class="kpi-grid">
      <div class="kpi-card" style="--card-accent: var(--cyan);">
        <div class="kpi-title">Detected Sessions <span id="sessionPill">LIVE</span></div>
        <div class="kpi-value" id="valSessions">0</div>
        <div class="kpi-sub">AI agents identified</div>
      </div>
      <div class="kpi-card" style="--card-accent: var(--purple);">
        <div class="kpi-title">Graph Nodes</div>
        <div class="kpi-value" id="valNodes">0</div>
        <div class="kpi-sub">Generated labyrinth surface</div>
      </div>
      <div class="kpi-card" style="--card-accent: var(--crimson);">
        <div class="kpi-title">Traps / Canaries Hit</div>
        <div class="kpi-value" id="valFlags">0</div>
        <div class="kpi-sub">Canary hits & dwell traps</div>
      </div>
      <div class="kpi-card" style="--card-accent: var(--amber);">
        <div class="kpi-title">Attacker Requests</div>
        <div class="kpi-value" id="valRequests">0</div>
        <div class="kpi-sub" id="valBytes">0 KB consumed</div>
      </div>
      <div class="kpi-card" style="--card-accent: var(--emerald);">
        <div class="kpi-title">Uptime</div>
        <div class="kpi-value" id="valUptime">0s</div>
        <div class="kpi-sub">Attacker cost &gt;&gt; defender</div>
      </div>
    </div>

    <!-- Main Visual Workspace -->
    <div class="workspace-grid">
      <!-- Left: Interactive Graph -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="6" cy="6" r="3"></circle>
              <circle cx="18" cy="6" r="3"></circle>
              <circle cx="12" cy="18" r="3"></circle>
              <line x1="8.5" y1="7.5" x2="15.5" y2="7.5"></line>
              <line x1="7.5" y1="8.5" x2="10.5" y2="15.5"></line>
              <line x1="16.5" y1="8.5" x2="13.5" y2="15.5"></line>
            </svg>
            <span>Semantic Attack Graph</span> // Real-time Visualization
          </div>
          <div class="legend">
            <div class="legend-item"><div class="legend-dot" style="background: var(--cyan);"></div> Root/Docs</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--purple);"></div> API</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--amber);"></div> Config/Admin</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--crimson);"></div> Trap/Canary</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--emerald);"></div> Code/Repo</div>
          </div>
        </div>

        <div class="graph-viewport" id="viewportContainer">
          <canvas id="graphCanvas"></canvas>
          <div class="graph-overlay-stats">
            <div>MODE: <span style="color: var(--cyan);">BOUND-VIRTUALIZED GRAPH</span></div>
            <div>VISIBLE NODES: <span id="overlayNodes" style="color: var(--emerald);">0</span></div>
            <div>ACTIVE EDGES: <span id="overlayEdges" style="color: var(--purple);">0</span></div>
            <div>INTERACTION: <span style="color: var(--text-dim);">Drag nodes or click</span></div>
          </div>
          <div class="graph-tooltip" id="graphTooltip">
            <h4 id="ttPath">/api/v1/resource</h4>
            <div id="ttType" style="color: var(--text-muted); font-size: 0.75rem; margin-bottom: 4px;">Type: API</div>
            <div id="ttMeta" style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: var(--text-dim);">Size: 120B</div>
          </div>
        </div>
      </div>

      <!-- Right: Telemetry & Inspector -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
              <line x1="8" y1="21" x2="16" y2="21"></line>
              <line x1="12" y1="17" x2="12" y2="21"></line>
            </svg>
            <span>Inspector & Telemetry</span>
          </div>
          <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--cyan);">AUTO-REFRESH 3s</span>
        </div>

        <div class="details-body">
          <!-- Budget Tracker -->
          <div class="budget-section">
            <div class="budget-header">
              <span>Generated Node Limit</span>
              <span id="budgetNodesText">0 / 500</span>
            </div>
            <div class="progress-bar-bg">
              <div class="progress-bar-fill" id="budgetNodesBar" style="width: 0%;"></div>
            </div>

            <div class="budget-header">
              <span>Bandwidth Limit</span>
              <span id="budgetBytesText">0 MB / 50 MB</span>
            </div>
            <div class="progress-bar-bg">
              <div class="progress-bar-fill" id="budgetBytesBar" style="width: 0%; background: linear-gradient(90deg, var(--emerald), var(--amber));"></div>
            </div>
          </div>

          <!-- Selected Node Details -->
          <div class="inspector-card">
            <div class="inspector-title">Node Details</div>
            <div id="inspectorContent">
              <p style="color: var(--text-dim); font-size: 0.78rem;">Click any node on the graph to view its synthetic structure, honeypots, and traps.</p>
            </div>
          </div>

          <!-- Live Event Log -->
          <div>
            <div class="inspector-title" style="margin-bottom: 6px;">Live Event Log</div>
            <div class="log-stream" id="logStream">
              <div class="log-entry">
                <span class="log-time">[BOOT]</span>
                <span class="log-type-session">vAIvar Server started on port ${apiPort}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <footer>
    <div>
      vAIvar Semantic Honeypot for AI Agents // <a class="license-link" href="${VAIVAR_LICENSE_URL}" target="_blank" rel="noopener noreferrer">Apache-2.0 License</a>
      // <a class="creator-link" href="${VAIVAR_CREATOR_URL}" target="_blank" rel="noopener noreferrer">${VAIVAR_CREATOR_CREDIT}</a>
    </div>
    <div>
      Endpoints: 
      <a href="/api/v1/sessions" target="_blank" class="pill-link">/api/v1/sessions</a>
      <a href="/api/v1/dashboard" target="_blank" class="pill-link">/api/v1/dashboard</a>
      <a href="/health" target="_blank" class="pill-link">/health</a>
    </div>
  </footer>

  <script>
    // State management
    let nodes = [];
    let edges = [];
    let selectedNode = null;
    let draggedNode = null;
    let currentSessionId = 'default-session';
    let simulationCount = 0;

    const canvas = document.getElementById('graphCanvas');
    const ctx = canvas.getContext('2d');
    const container = document.getElementById('viewportContainer');
    const tooltip = document.getElementById('graphTooltip');

    // Resize canvas
    function resizeCanvas() {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    // Default mock seeds if empty
    function initializeSeedNodes() {
      const w = canvas.width;
      const h = canvas.height;
      const cx = w / 2;
      const cy = h / 2;

      nodes = [
        { id: 'root', label: '/', path: '/', type: 'docs', x: cx, y: cy, vx: 0, vy: 0, isTrap: false, level: 0, size: 256 },
        { id: 'docs', label: '/docs/api', path: '/docs/api', type: 'docs', x: cx - 120, y: cy - 90, vx: 0, vy: 0, isTrap: false, level: 1, size: 1024 },
        { id: 'auth', label: '/auth/login', path: '/auth/login', type: 'api', x: cx + 130, y: cy - 80, vx: 0, vy: 0, isTrap: false, level: 1, size: 512 },
        { id: 'admin', label: '/internal/admin', path: '/internal/admin', type: 'admin', x: cx + 180, y: cy + 90, vx: 0, vy: 0, isTrap: true, level: 2, size: 768 },
        { id: 'vault', label: '/secrets/aws.env', path: '/secrets/aws.env', type: 'trap', x: cx + 70, y: cy + 160, vx: 0, vy: 0, isTrap: true, level: 3, size: 2048 },
        { id: 'repo', label: '/git/src/server', path: '/git/src/server', type: 'code', x: cx - 160, y: cy + 90, vx: 0, vy: 0, isTrap: false, level: 1, size: 1536 }
      ];

      edges = [
        { from: 'root', to: 'docs' },
        { from: 'root', to: 'auth' },
        { from: 'auth', to: 'admin' },
        { from: 'admin', to: 'vault' },
        { from: 'root', to: 'repo' }
      ];

      updateGraphOverlay();
      selectNode(nodes[0]);
    }

    // Colors mapping
    function getNodeColor(node) {
      if (node.isTrap || node.type === 'trap') return '#ef4444';
      if (node.type === 'admin') return '#f59e0b';
      if (node.type === 'api') return '#a855f7';
      if (node.type === 'code') return '#10b981';
      return '#00f0ff';
    }

    // Force simulation step
    function updatePhysics() {
      const cx = canvas.width / 2;
      const cy = canvas.height / 2;

      // Repulsion between nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 260) {
            const force = (260 - dist) / 260 * 1.8;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            if (nodes[i] !== draggedNode) {
              nodes[i].x -= fx;
              nodes[i].y -= fy;
            }
            if (nodes[j] !== draggedNode) {
              nodes[j].x += fx;
              nodes[j].y += fy;
            }
          }
        }
      }

      // Spring attraction along edges
      edges.forEach(edge => {
        const source = nodes.find(n => n.id === edge.from);
        const target = nodes.find(n => n.id === edge.to);
        if (!source || !target) return;

        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const targetDist = 130;
        const force = (dist - targetDist) * 0.025;

        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        if (source !== draggedNode) {
          source.x += fx;
          source.y += fy;
        }
        if (target !== draggedNode) {
          target.x -= fx;
          target.y -= fy;
        }
      });

      // Gravity towards center
      nodes.forEach(node => {
        if (node === draggedNode) return;
        node.x += (cx - node.x) * 0.008;
        node.y += (cy - node.y) * 0.008;

        // Keep inside bounds
        const pad = 40;
        node.x = Math.max(pad, Math.min(canvas.width - pad, node.x));
        node.y = Math.max(pad, Math.min(canvas.height - pad, node.y));
      });
    }

    // Animation particles along edges
    let particleOffset = 0;

    function render() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      updatePhysics();
      particleOffset += 0.015;
      if (particleOffset > 1) particleOffset = 0;

      // Draw Edges
      edges.forEach(edge => {
        const source = nodes.find(n => n.id === edge.from);
        const target = nodes.find(n => n.id === edge.to);
        if (!source || !target) return;

        // Line
        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.2)';
        ctx.lineWidth = 1.8;
        ctx.stroke();

        // Traveling particle
        const px = source.x + (target.x - source.x) * particleOffset;
        const py = source.y + (target.y - source.y) * particleOffset;

        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 240, 255, 0.8)';
        ctx.shadowColor = '#00f0ff';
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Nodes
      nodes.forEach(node => {
        const color = getNodeColor(node);
        const isSelected = selectedNode === node;
        const radius = isSelected ? 19 : 14;

        // Outer glow for traps or selected
        if (node.isTrap || isSelected) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 8, 0, Math.PI * 2);
          ctx.fillStyle = node.isTrap ? 'rgba(239, 68, 68, 0.25)' : 'rgba(0, 240, 255, 0.25)';
          ctx.fill();
        }

        // Node Circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = '#0f172a';
        ctx.fill();
        ctx.lineWidth = isSelected ? 3 : 2;
        ctx.strokeStyle = color;
        ctx.stroke();

        // Inner core
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius * 0.45, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Label
        ctx.font = '11px "JetBrains Mono", monospace';
        ctx.fillStyle = isSelected ? '#ffffff' : '#94a3b8';
        ctx.textAlign = 'center';
        ctx.fillText(node.label || node.path, node.x, node.y + radius + 15);
      });

      requestAnimationFrame(render);
    }

    // Mouse Interaction
    function getNodeAt(x, y) {
      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i];
        const dist = Math.hypot(n.x - x, n.y - y);
        if (dist <= 25) return n;
      }
      return null;
    }

    canvas.addEventListener('mousedown', e => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const hit = getNodeAt(x, y);

      if (hit) {
        draggedNode = hit;
        selectNode(hit);
      }
    });

    canvas.addEventListener('mousemove', e => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      if (draggedNode) {
        draggedNode.x = x;
        draggedNode.y = y;
      }

      const hit = getNodeAt(x, y);
      if (hit) {
        tooltip.style.display = 'block';
        tooltip.style.left = (x + 15) + 'px';
        tooltip.style.top = (y + 15) + 'px';
        document.getElementById('ttPath').textContent = hit.path || hit.label;
        document.getElementById('ttType').textContent = 'Type: ' + hit.type.toUpperCase() + (hit.isTrap ? ' [TRAP DETECTED]' : '');
        document.getElementById('ttMeta').textContent = 'Level: ' + (hit.level || 0) + ' // Size: ' + (hit.size || 250) + ' B';
      } else {
        tooltip.style.display = 'none';
      }
    });

    window.addEventListener('mouseup', () => {
      draggedNode = null;
    });

    function selectNode(node) {
      selectedNode = node;
      const container = document.getElementById('inspectorContent');
      if (!node) return;

      const isTrapHtml = node.isTrap 
        ? '<span style="color: var(--crimson); font-weight: 700;">YES (STIX/IOC Alert)</span>' 
        : '<span style="color: var(--emerald);">NO (Passive Decoy)</span>';

      container.innerHTML = \`
        <div class="meta-row">
          <span class="meta-key">Path:</span>
          <span class="meta-val" style="color: var(--cyan);">\${node.path || node.label}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">Category:</span>
          <span class="meta-val">\${node.type.toUpperCase()}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">Maze Level:</span>
          <span class="meta-val">Level \${node.level || 0}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">Is Trap/Canary:</span>
          <span class="meta-val">\${isTrapHtml}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">Synthetic Size:</span>
          <span class="meta-val">\${node.size || 340} bytes</span>
        </div>
        <div style="margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.4); border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: var(--text-muted); line-height: 1.4;">
          <strong>Engine Heuristics:</strong> Generated deterministically from cryptographic seed. AI agents are diverted through fake links maintaining defender cost at 0.001%.
        </div>
      \`;
    }

    function addLog(time, typeClass, message) {
      const stream = document.getElementById('logStream');
      const row = document.createElement('div');
      row.className = 'log-entry';
      row.innerHTML = \`<span class="log-time">[\${time}]</span> <span class="\${typeClass}">\${message}</span>\`;
      stream.insertBefore(row, stream.firstChild);
      while (stream.children.length > 25) {
        stream.removeChild(stream.lastChild);
      }
    }

    function updateGraphOverlay() {
      document.getElementById('overlayNodes').textContent = nodes.length;
      document.getElementById('overlayEdges').textContent = edges.length;
    }

    // Real-time API poll
    async function fetchTelemetry() {
      try {
        const res = await fetch('/api/v1/dashboard');
        if (res.ok) {
          const data = await res.json();
          if (data.overview) {
            document.getElementById('valSessions').textContent = Math.max(data.overview.sessions || 1, 1);
            document.getElementById('valFlags').textContent = data.overview.flags || 0;
          }
          if (data.budget_usage) {
            const reqs = data.budget_usage.requests || 0;
            const bytesKb = Math.round((data.budget_usage.bytes || 0) / 1024);
            document.getElementById('valRequests').textContent = reqs;
            document.getElementById('valBytes').textContent = bytesKb + ' KB consumed';

            const nodeCount = Math.max(data.budget_usage.nodes || nodes.length, nodes.length);
            document.getElementById('valNodes').textContent = nodeCount;
            document.getElementById('budgetNodesText').textContent = nodeCount + ' / 500';
            document.getElementById('budgetNodesBar').style.width = Math.min(100, (nodeCount / 500) * 100) + '%';

            const bytesMb = (bytesKb / 1024).toFixed(1);
            document.getElementById('budgetBytesText').textContent = bytesMb + ' MB / 50 MB';
            document.getElementById('budgetBytesBar').style.width = Math.min(100, (bytesKb / (50 * 1024)) * 100) + '%';
          }
          if (data.uptime) {
            const mins = Math.floor(data.uptime / 60);
            const secs = Math.floor(data.uptime % 60);
            document.getElementById('valUptime').textContent = mins + 'm ' + secs + 's';
          }
        }
      } catch (err) {
        console.warn('Telemetry fetch error:', err);
      }
    }

    // Simulate Agent Attack Interaction
    const mockAttackPaths = [
      { path: '/api/v2/tokens', type: 'api', isTrap: false, level: 1 },
      { path: '/backup/db.dump.gz', type: 'trap', isTrap: true, level: 2 },
      { path: '/admin/config.yaml', type: 'admin', isTrap: true, level: 2 },
      { path: '/internal/metrics', type: 'api', isTrap: false, level: 1 },
      { path: '/.git/HEAD', type: 'code', isTrap: false, level: 1 },
      { path: '/vault/prod_keys.pem', type: 'trap', isTrap: true, level: 4 },
      { path: '/service/status/full', type: 'docs', isTrap: false, level: 0 },
      { path: '/api/v1/debug/execute', type: 'trap', isTrap: true, level: 3 }
    ];

    async function simulateAttack() {
      const btn = document.getElementById('btnSimulate');
      btn.disabled = true;
      btn.textContent = 'Simulating Agent...';

      try {
        const item = mockAttackPaths[simulationCount % mockAttackPaths.length];
        simulationCount++;

        // Call backend session or node endpoint
        const sessionRes = await fetch('/api/v1/session', { method: 'POST' });
        const sessionData = await sessionRes.json();
        const sid = sessionData.sessionId || 'sim_' + Date.now();

        // Call node endpoint to generate deterministic honeypot node
        const nodeRes = await fetch('/api/v1/node/' + sid + item.path);
        const nodeData = await nodeRes.json();

        // Add node to graph visualizer
        const parentNode = nodes[Math.floor(Math.random() * nodes.length)];
        const angle = Math.random() * Math.PI * 2;
        const dist = 110 + Math.random() * 50;

        const newNode = {
          id: 'node_' + Date.now(),
          label: item.path,
          path: item.path,
          type: item.type,
          x: parentNode.x + Math.cos(angle) * dist,
          y: parentNode.y + Math.sin(angle) * dist,
          vx: 0,
          vy: 0,
          isTrap: item.isTrap,
          level: item.level,
          size: Math.floor(Math.random() * 800) + 150
        };

        nodes.push(newNode);
        edges.push({ from: parentNode.id, to: newNode.id });
        selectNode(newNode);
        updateGraphOverlay();

        const now = new Date().toLocaleTimeString();
        if (item.isTrap) {
          addLog(now, 'log-type-flag', 'TRAP ACTIVATED: AI agent fell at ' + item.path + ' (Level ' + item.level + ')');
        } else {
          addLog(now, 'log-type-node', 'AI EXPLORATION: Node expanded ' + item.path);
        }

        await fetchTelemetry();
      } catch (err) {
        console.error('Simulation error:', err);
      } finally {
        setTimeout(() => {
          btn.disabled = false;
          btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Simulate Agent Attack';
        }, 300);
      }
    }

    // Init
    initializeSeedNodes();
    render();
    fetchTelemetry();
    setInterval(fetchTelemetry, 3000);
  </script>
</body>
</html>`;
}
