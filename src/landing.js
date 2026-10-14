/**
 * Built-in Interactive Web Console & Landing Page for cf-doh.
 *
 * Implements awesome-ui-kit modern frontend architecture:
 *  - Pure ESM, zero-external-dependency, self-contained single-page console
 *  - UiIcon Tabler-compliant SVG vector icon engine (eliminating raw emojis)
 *  - Embedded <theme-toggle> (Auto / Light / Dark) & <status-indicator> Web Components
 *  - Interactive DNS Playground with structured record inspection, latency profiling & Raw JSON switch
 *  - Real-time Concurrency Racing & Telemetry Dashboard (Local PoP vs Global Analytics Engine)
 *  - Comprehensive multi-platform client configuration guides (Mihomo, Surge, Sing-box, Android DoT, Win11, etc.)
 */

export function renderLandingHtml(origin, config) {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="auto">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cf-doh — 高性能自研 Cloudflare Workers DoH/DoT 解析网关</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 fill=%22none%22 stroke=%22%233b82f6%22 stroke-width=%222%22 stroke-linecap=%22round%22 stroke-linejoin=%22round%22><polygon points=%2213 2 3 14 12 14 11 22 21 10 12 10 13 2%22/></svg>">
  <script>
    (function() {
      try {
        var mode = localStorage.getItem('cf-doh-theme') || 'auto';
        var resolved = mode;
        if (mode === 'auto') {
          var isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          resolved = isDark ? 'dark' : 'light';
        }
        document.documentElement.dataset.theme = mode;
        document.documentElement.dataset.resolvedTheme = resolved;
        if (resolved === 'dark') {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
      } catch (e) {}
    })();
  </script>
  <style>
    :root {
      --bg: #101418;
      --bg-subtle: #171d22;
      --card-bg: #171d22;
      --card-border: #2a333a;
      --card-hover-border: #48616a;
      --text: #e8edf0;
      --text-muted: #a0adb4;
      --text-faint: #78878f;
      --primary: #70c7bd;
      --primary-hover: #8bd8ce;
      --primary-glow: rgba(112, 199, 189, 0.12);
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #ef4444;
      --accent-purple: #8b5cf6;
      --accent-orange: #f97316;
      --code-bg: #11171b;
      --chip-bg: #1b2328;
      --chip-border: #303b42;
      --nav-bg: rgba(16, 20, 24, 0.94);
    }
    html:not(.dark) {
      --bg: #f3f6f6;
      --bg-subtle: #e9eeee;
      --card-bg: #ffffff;
      --card-border: #dce4e5;
      --card-hover-border: #9abbb7;
      --text: #192326;
      --text-muted: #58686d;
      --text-faint: #829094;
      --primary: #187d73;
      --primary-hover: #12675f;
      --primary-glow: rgba(24, 125, 115, 0.1);
      --accent-emerald: #059669;
      --accent-amber: #d97706;
      --accent-rose: #dc2626;
      --accent-purple: #7c3aed;
      --accent-orange: #ea580c;
      --code-bg: #f5f8f8;
      --chip-bg: #f6f8f8;
      --chip-border: #dce4e5;
      --nav-bg: rgba(243, 246, 246, 0.94);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.55;
      overflow-x: hidden;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      transition: background-color 0.25s ease, color 0.25s ease;
    }
    a { color: var(--primary); text-decoration: none; transition: color 0.2s; }
    a:hover { color: var(--primary-hover); text-decoration: underline; }
    
    /* Navigation Bar */
    .nav-bar {
      position: sticky;
      top: 0;
      z-index: 50;
      background: var(--nav-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--card-border);
      padding: 10px 28px;
    }
    .nav-inner {
      max-width: 1220px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 9px;
      font-weight: 700;
      font-size: 1rem;
      letter-spacing: -0.01em;
      color: var(--text);
    }
    .brand-icon {
      width: 30px;
      height: 30px;
      border-radius: 7px;
      background: linear-gradient(135deg, var(--primary) 0%, #187d73 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
    }
    .version-tag {
      font-size: 0.68rem;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: 5px;
      background: var(--primary-glow);
      color: var(--primary);
      border: 1px solid var(--card-border);
    }
    .nav-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    /* Layout Container */
    .container {
      max-width: 1220px;
      margin: 0 auto;
      padding: 34px 24px 64px;
      width: 100%;
      flex: 1;
    }
    
    /* Hero Header */
    .hero {
      text-align: left;
      margin: 0 0 28px;
      padding: 8px 0 24px;
      border-bottom: 1px solid var(--card-border);
    }
    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 4px 9px;
      border-radius: 5px;
      font-size: 0.76rem;
      font-weight: 500;
      background: var(--primary-glow);
      color: var(--primary);
      border: 1px solid var(--card-border);
      margin-bottom: 12px;
    }
    .hero h1 {
      font-size: 2rem;
      font-weight: 700;
      letter-spacing: 0;
      margin-bottom: 8px;
      color: var(--text);
    }
    .hero-desc {
      font-size: 0.96rem;
      color: var(--text-muted);
      max-width: 780px;
      margin: 0;
    }
    .feature-tags {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-start;
      gap: 7px;
      margin-top: 17px;
    }
    .feature-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--chip-bg);
      border: 1px solid var(--chip-border);
      padding: 4px 9px;
      border-radius: 5px;
      font-size: 0.76rem;
      font-weight: 500;
      color: var(--text-muted);
    }
    .feature-tag svg {
      color: var(--primary);
    }
    
    /* Grid system */
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
      margin-bottom: 22px;
    }
    @media (min-width: 840px) {
      .grid-2 { grid-template-columns: minmax(0, 1.15fr) minmax(360px, 0.85fr); }
    }
    @media (min-width: 1024px) {
      .grid-3 { grid-template-columns: repeat(3, 1fr); }
      .grid-4 { grid-template-columns: repeat(4, 1fr); }
    }
    
    /* Modern Card */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);
      transition: border-color 0.2s;
    }
    .card:hover {
      border-color: var(--card-hover-border);
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--card-border);
    }
    .card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 1rem;
      font-weight: 600;
      letter-spacing: 0;
    }
    .card-title-icon {
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary);
    }
    .card-title-icon svg {
      width: 18px;
      height: 18px;
    }
    
    /* Inputs & Form Elements */
    .input-group {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    @media (min-width: 540px) {
      .input-group { flex-wrap: nowrap; }
    }
    input[type="text"] {
      flex: 1;
      min-width: 180px;
      min-height: 40px;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="text"]:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px var(--primary-glow);
    }
    select {
      min-height: 40px;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      cursor: pointer;
      transition: border-color 0.2s;
    }
    select:focus {
      border-color: var(--primary);
    }
    button.btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      min-height: 40px;
      padding: 8px 16px;
      background: var(--primary);
      color: #101418;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      transition: background-color 0.15s;
      white-space: nowrap;
    }
    html.dark button.btn {
      color: #101418;
    }
    html:not(.dark) button.btn {
      color: #ffffff;
    }
    button.btn:hover {
      background: var(--primary-hover);
    }
    button.btn-secondary {
      background: var(--chip-bg);
      color: var(--text);
      border: 1px solid var(--card-border);
    }
    button.btn-secondary:hover {
      background: var(--primary-glow);
      color: var(--primary);
      border-color: var(--primary);
    }
    button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }
    
    /* Quick Domain Chips */
    .chips-group {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-bottom: 16px;
    }
    .chips-label {
      font-size: 0.78rem;
      color: var(--text-faint);
      margin-right: 4px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: var(--chip-bg);
      border: 1px solid var(--chip-border);
      padding: 4px 10px;
      border-radius: 5px;
      font-size: 0.8rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.18s;
      user-select: none;
    }
    .chip:hover {
      color: var(--primary);
      border-color: var(--primary);
      background: var(--primary-glow);
    }
    
    /* Code & Output Blocks */
    .code-block {
      position: relative;
      background: var(--code-bg);
      border-radius: 6px;
      padding: 12px 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      border: 1px solid var(--card-border);
      overflow-x: auto;
      margin-bottom: 12px;
    }
    .code-block code {
      color: var(--text);
      word-break: break-all;
    }
    .copy-btn {
      position: absolute;
      top: 8px;
      right: 8px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: var(--text-muted);
      border-radius: 5px;
      padding: 4px 9px;
      font-size: 0.75rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.18s;
    }
    html:not(.dark) .copy-btn {
      background: rgba(0, 0, 0, 0.05);
      border-color: rgba(0, 0, 0, 0.1);
      color: var(--text-muted);
    }
    .copy-btn:hover {
      background: var(--primary);
      color: #101418;
      border-color: var(--primary);
    }
    html:not(.dark) .copy-btn:hover {
      color: #ffffff;
    }
    
    /* Result Playground Box */
    .playground-result {
      background: var(--code-bg);
      border-radius: 6px;
      padding: 16px;
      border: 1px solid var(--card-border);
      min-height: 120px;
    }
    .meta-badges {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 14px;
      padding-bottom: 12px;
      border-bottom: 1px dashed var(--card-border);
    }
    .meta-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 5px;
      font-size: 0.78rem;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
    }
    .meta-badge.success {
      background: rgba(16, 185, 129, 0.12);
      color: var(--accent-emerald);
      border-color: rgba(16, 185, 129, 0.25);
    }
    .meta-badge.warn {
      background: rgba(245, 158, 11, 0.12);
      color: var(--accent-amber);
      border-color: rgba(245, 158, 11, 0.25);
    }
    .meta-badge.error {
      background: rgba(239, 68, 68, 0.12);
      color: var(--accent-rose);
      border-color: rgba(239, 68, 68, 0.25);
    }
    .meta-badge.info {
      background: var(--primary-glow);
      color: var(--primary);
      border-color: rgba(112, 199, 189, 0.25);
    }
    
    /* Record Table */
    .record-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-top: 8px;
      table-layout: fixed;
    }
    .record-table th {
      text-align: left;
      padding: 8px;
      color: var(--text-faint);
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .record-table td {
      padding: 8px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      word-break: break-all;
    }
    html:not(.dark) .record-table td {
      border-bottom-color: rgba(0, 0, 0, 0.04);
    }
    .record-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .record-type-pill {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      background: var(--primary-glow);
      color: var(--primary);
    }
    
    /* View Switcher */
    .view-switcher {
      display: inline-flex;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 2px;
      gap: 2px;
      margin-left: auto;
    }
    html:not(.dark) .view-switcher {
      background: rgba(0, 0, 0, 0.04);
    }
    .view-btn {
      min-height: 30px;
      padding: 4px 10px;
      font-size: 0.75rem;
      border-radius: 4px;
      border: none;
      background: transparent;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 500;
      transition: all 0.15s;
    }
    .view-btn.active {
      background: var(--primary);
      color: #101418;
      font-weight: 600;
    }
    html:not(.dark) .view-btn.active {
      color: #ffffff;
    }
    
    /* Racing Telemetry Cards */
    .metric-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      font-size: 0.9rem;
      font-weight: 600;
    }
    .progress-bar-container {
      display: flex;
      height: 8px;
      border-radius: 9999px;
      overflow: hidden;
      background: rgba(255, 255, 255, 0.08);
      margin-bottom: 10px;
    }
    html:not(.dark) .progress-bar-container {
      background: rgba(0, 0, 0, 0.08);
    }
    .progress-bar-fill {
      height: 100%;
      transition: width 0.45s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .latency-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px dashed var(--card-border);
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .latency-grid b {
      display: block;
      color: var(--text);
      font-size: 0.92rem;
      margin-top: 2px;
    }
    
    /* Tabs for Client Configuration */
    .tabs-header {
      display: flex;
      gap: 3px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 16px;
      overflow-x: auto;
      padding-bottom: 8px;
      scrollbar-width: thin;
    }
    .tab-btn {
      padding: 6px 10px;
      border-radius: 5px;
      font-size: 0.86rem;
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 500;
      white-space: nowrap;
      transition: all 0.18s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .tab-btn:hover {
      color: var(--text);
      background: var(--chip-bg);
    }
    .tab-btn.active {
      background: var(--primary-glow);
      color: var(--primary);
      border-color: transparent;
      box-shadow: inset 0 -2px var(--primary);
      font-weight: 600;
    }
    
    /* Feature Matrix List */
    .feature-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 7px;
      padding: 16px;
      display: flex;
      gap: 12px;
      align-items: flex-start;
      transition: border-color 0.2s;
    }
    .feature-card:hover {
      border-color: var(--card-hover-border);
    }
    .feature-icon-wrapper {
      width: 34px;
      height: 34px;
      border-radius: 7px;
      background: var(--primary-glow);
      color: var(--primary);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    
    /* Footer */
    footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 0.88rem;
      padding: 24px 20px;
      border-top: 1px solid var(--card-border);
      background: transparent;
    }
    .footer-links {
      display: flex;
      justify-content: center;
      gap: 18px;
      margin-bottom: 10px;
      flex-wrap: wrap;
    }
    
    /* Notification Toast */
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--primary);
      color: #101418;
      padding: 10px 18px;
      border-radius: 6px;
      font-size: 0.88rem;
      font-weight: 600;
      box-shadow: 0 10px 25px rgba(0,0,0,0.3);
      display: flex;
      align-items: center;
      gap: 8px;
      z-index: 100;
      opacity: 0;
      transform: translateY(12px);
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      pointer-events: none;
    }
    html:not(.dark) .toast {
      color: #ffffff;
    }
    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }

    /* Status indicator label targeting */
    .status-indicator-label {
      display: inline-block;
    }

    /* Mobile Responsive Breakpoints */
    @media (max-width: 700px) {
      .nav-bar { padding: 9px 14px; }
      .nav-actions { gap: 6px; }
      #globalGatewayStatus > div { max-width: 118px; padding: 3px 7px !important; }
      #globalGatewayStatus .status-indicator-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      theme-toggle button span { display: none; }
      theme-toggle button { padding: 5px 7px !important; }
      .container { padding: 24px 14px 42px; }
      .hero { padding-bottom: 18px; margin-bottom: 18px; }
      .hero h1 { font-size: 1.65rem; }
      .hero-desc { font-size: 0.9rem; }
      .feature-tags { gap: 6px; }
      .feature-tag { font-size: 0.71rem; }
      .card { padding: 15px; }
      .card-header { align-items: flex-start; flex-wrap: wrap; }
      .card-header > .view-switcher { margin-left: 0; }
      .card-header > div:last-child { max-width: 100%; }
      .input-group { flex-wrap: wrap; }
      .input-group input[type="text"] { flex-basis: 100%; }
      .input-group select { flex: 1; }
      .view-switcher { margin-left: 0; }
      .record-table { font-size: 0.76rem; }
      .record-table th, .record-table td { padding: 6px 4px; }
      .record-table th:nth-child(1), .record-table td:nth-child(1) { display: none; }
      .record-table th:nth-child(5), .record-table td:nth-child(5) { width: 56px; }
      .record-table .btn { white-space: normal; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        scroll-behavior: auto !important;
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <!-- Top Navigation -->
  <header class="nav-bar">
    <div class="nav-inner">
      <div class="nav-brand">
        <div class="brand-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </div>
        <span>cf-doh</span>
        <span class="version-tag">v1.2.0</span>
      </div>
      <div class="nav-actions">
        <status-indicator id="globalGatewayStatus" status="online" label="边缘探测中..." show-dot="true"></status-indicator>
        <theme-toggle storage-key="cf-doh-theme"></theme-toggle>
      </div>
    </div>
  </header>

  <main class="container">
    <!-- Hero Section -->
    <section class="hero">
      <div class="hero-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.2 4.8L6 9l4.8 1.2L12 15l1.2-4.8L18 9l-4.8-1.2L12 3Z"/></svg>
        <span>Cloudflare Workers • RFC 8484 / RFC 7858 • 双栈解析</span>
      </div>
      <h1>cf-doh 解析网关</h1>
      <p class="hero-desc">
        专为国内网络环境深度优化的自研高性能 DoH / DoT 解析服务。内置国内外智能分流、真实可信出口 ECS 注入、上游并发全速竞价与 Android 私人 DNS 原生支持。
      </p>
      <div class="feature-tags">
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          <span>并发全速竞价 (Zero Penalty)</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/></svg>
          <span>可信真实 ECS 注入</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="8" rx="2"/><rect x="3" y="12" width="18" height="8" rx="2"/><line x1="7" y1="8" x2="7.01" y2="8"/><line x1="7" y1="16" x2="7.01" y2="16"/></svg>
          <span>阿里 / 腾讯 直连分流</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>
          <span>Google / CF 全球兜底</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
          <span>DNSSEC 真实 AD 透传</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="4" width="10" height="16" rx="2"/><line x1="11" y1="17" x2="13" y2="17"/></svg>
          <span>Android 私人 DNS (DoT 853)</span>
        </div>
      </div>
    </section>

    <!-- Two-column Main Section: Playground & Endpoints -->
    <div class="grid grid-2">
      <!-- 在线解析测试台 -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <span class="card-title-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polygon points="12 6 12 12 16 14"/></svg>
            </span>
            <span>在线解析测试台 (Live Playground)</span>
          </div>
          <div class="view-switcher">
            <button id="viewFormattedBtn" class="view-btn active" onclick="switchResultView('formatted')">结构化卡片</button>
            <button id="viewRawBtn" class="view-btn" onclick="switchResultView('raw')">Raw JSON</button>
          </div>
        </div>

        <p style="font-size:0.86rem; color:var(--text-muted); margin-bottom:12px;">
          直接在浏览器内向网关发送解析请求，实时观测分流决策、响应记录与实测链路时延：
        </p>

        <!-- 快捷测试标签 -->
        <div class="chips-group">
          <span class="chips-label">预设:</span>
          <span class="chip" onclick="setQuery('linux.do', 'A')">linux.do (国内组)</span>
          <span class="chip" onclick="setQuery('github.com', 'A')">github.com (国内直连)</span>
          <span class="chip" onclick="setQuery('bilibili.com', 'A')">bilibili.com (CDN节点)</span>
          <span class="chip" onclick="setQuery('google.com', 'A')">google.com (全球组)</span>
          <span class="chip" onclick="setQuery('cloudflare.com', 'A')">cloudflare.com (DNSSEC)</span>
          <span class="chip" onclick="setQuery('apple.com', 'HTTPS')">apple.com (HTTPS)</span>
        </div>

        <!-- 查询输入区 -->
        <div class="input-group">
          <input type="text" id="domainInput" placeholder="输入待解析域名 (如 linux.do)" value="linux.do" onkeydown="if(event.key==='Enter') runQuery();">
          <select id="typeSelect">
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="CNAME">CNAME</option>
            <option value="TXT">TXT</option>
            <option value="HTTPS">HTTPS (Type 65)</option>
            <option value="MX">MX</option>
            <option value="NS">NS</option>
            <option value="SOA">SOA</option>
          </select>
          <button class="btn" id="queryBtn" onclick="runQuery()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="7"/><line x1="21" y1="21" x2="15" y2="15"/></svg>
            <span>查询</span>
          </button>
        </div>

        <!-- 结果展示面板 -->
        <div class="playground-result" id="playgroundResult">
          <div style="color:var(--text-faint); font-size:0.85rem; padding: 20px 0; text-align: center;">
            点击上方「查询」或快捷域名标签，开始实时测试...
          </div>
        </div>
      </div>

      <!-- 核心端点服务矩阵 -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <span class="card-title-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
            </span>
            <span>服务接入端点矩阵</span>
          </div>
          <span style="font-size:0.78rem; color:var(--text-muted);">生产就绪</span>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>RFC 8484 标准 DoH URL</span>
            <span style="color:var(--primary); font-weight:600;">HTTPS 443</span>
          </div>
          <div class="code-block">
            <code>${origin}${config.path}</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.path}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
              <span>复制</span>
            </button>
          </div>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>RFC 7858 DoT (Android 私人 DNS)</span>
            <span style="color:var(--accent-emerald); font-weight:600;">TLS 853</span>
          </div>
          <div class="code-block">
            <code>2fa.mangoqwq.com</code>
            <button class="copy-btn" onclick="copyText('2fa.mangoqwq.com')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
              <span>复制主机名</span>
            </button>
          </div>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>Google 风格 DoH JSON API</span>
            <span style="color:var(--text-faint);">RFC 8427 兼容</span>
          </div>
          <div class="code-block">
            <code>${origin}${config.jsonPath}?name=linux.do&type=A</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.jsonPath}?name=linux.do&type=A')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
              <span>复制</span>
            </button>
          </div>
        </div>

        <div>
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>监控与度量端点</span>
            <span style="color:var(--text-faint);">Prometheus / JSON</span>
          </div>
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
            <div class="code-block" style="margin-bottom:0;">
              <code>/healthz</code>
              <button class="copy-btn" onclick="copyText('${origin}/healthz')">复制</button>
            </div>
            <div class="code-block" style="margin-bottom:0;">
              <code>/api/stats</code>
              <button class="copy-btn" onclick="copyText('${origin}/api/stats')">复制</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 上游并发竞速与延迟监控大屏 -->
    <section class="card" style="margin-bottom: 32px;">
      <div class="card-header">
        <div class="card-title">
          <span class="card-title-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </span>
          <span>上游并发竞速与延迟监控 (Racing & P95 Telemetry)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
          <div class="view-switcher" style="margin-left:0;">
            <button id="scopeLocalBtn" class="view-btn active" onclick="setStatsScope('local')">
              <span>本地 PoP 边缘</span>
            </button>
            <button id="scopeGlobalBtn" class="view-btn" onclick="setStatsScope('global')">
              <span>全球多地域聚合</span>
            </button>
          </div>
          <label style="display:inline-flex; align-items:center; gap:6px; font-size:0.8rem; color:var(--text-muted); cursor:pointer;">
            <input type="checkbox" id="autoRefreshCheckbox" onchange="toggleAutoRefresh(this.checked)" checked>
            <span>自动刷新 (10s)</span>
          </label>
          <button class="btn btn-secondary" style="padding: 5px 12px; font-size: 0.8rem;" id="refreshStatsBtn" onclick="loadStats()">
            <svg id="refreshIcon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14.5-4L3 10m0-5v5h5M4 13a8 8 0 0 0 14.5 4L21 14m0 5v-5h-5"/></svg>
            <span>刷新指标</span>
          </button>
        </div>
      </div>

      <div id="scopeNotice" style="font-size:0.82rem; color:var(--text-muted); margin-bottom:16px; padding:8px 14px; background:rgba(255,255,255,0.03); border-radius:8px; border-left:3px solid var(--primary);">
        统计范围：当前 Cloudflare 边缘节点内存实时采样 (单实例)
      </div>

      <div class="grid grid-2" style="margin-bottom: 20px;">
        <!-- 国内组竞速看板 -->
        <div style="background:var(--code-bg); padding:18px; border-radius:12px; border:1px solid var(--card-border);">
          <div class="metric-row">
            <span style="display:flex; align-items:center; gap:6px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="8" rx="2"/><rect x="3" y="12" width="18" height="8" rx="2"/><line x1="7" y1="8" x2="7.01" y2="8"/><line x1="7" y1="16" x2="7.01" y2="16"/></svg>
              <span>国内组竞速 (AliDNS vs DNSPod)</span>
            </span>
            <span id="domesticTotalWins" style="color:var(--text-muted); font-size:0.82rem; font-weight:normal;">0 次胜出</span>
          </div>
          <div class="progress-bar-container">
            <div id="barAlidns" class="progress-bar-fill" style="width:50%; background:#3b82f6;"></div>
            <div id="barDohpub" class="progress-bar-fill" style="width:50%; background:#10b981;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.82rem; color:var(--text-muted);">
            <span><span style="color:#3b82f6;">●</span> 阿里 DNS: <b id="winAlidns" style="color:var(--text);">0 (0.0%)</b></span>
            <span><span style="color:#10b981;">●</span> 腾讯 DNSPod: <b id="winDohpub" style="color:var(--text);">0 (0.0%)</b></span>
          </div>
          <div class="latency-grid">
            <div>P50 时延<b id="p50Domestic">- ms</b></div>
            <div>P95 时延<b id="p95Domestic" style="color:#f59e0b;">- ms</b></div>
            <div>平均时延<b id="avgDomestic">- ms</b></div>
          </div>
        </div>

        <!-- 全球组竞速看板 -->
        <div style="background:var(--code-bg); padding:18px; border-radius:12px; border:1px solid var(--card-border);">
          <div class="metric-row">
            <span style="display:flex; align-items:center; gap:6px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>
              <span>全球组竞速 (Google vs Cloudflare)</span>
            </span>
            <span id="globalTotalWins" style="color:var(--text-muted); font-size:0.82rem; font-weight:normal;">0 次胜出</span>
          </div>
          <div class="progress-bar-container">
            <div id="barGoogle" class="progress-bar-fill" style="width:50%; background:#8b5cf6;"></div>
            <div id="barCf" class="progress-bar-fill" style="width:50%; background:#f97316;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.82rem; color:var(--text-muted);">
            <span><span style="color:#8b5cf6;">●</span> Google DNS: <b id="winGoogle" style="color:var(--text);">0 (0.0%)</b></span>
            <span><span style="color:#f97316;">●</span> Cloudflare: <b id="winCf" style="color:var(--text);">0 (0.0%)</b></span>
          </div>
          <div class="latency-grid">
            <div>P50 时延<b id="p50Global">- ms</b></div>
            <div>P95 时延<b id="p95Global" style="color:#f59e0b;">- ms</b></div>
            <div>平均时延<b id="avgGlobal">- ms</b></div>
          </div>
        </div>
      </div>

      <!-- 概览指标行 -->
      <div style="display:flex; flex-wrap:wrap; gap:20px; font-size:0.85rem; color:var(--text-muted); padding-top:4px;">
        <span style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v3m0 12v3M3 12h3m12 0h3"/></svg>
          <span>边缘 LRU 缓存命中率:</span> <b id="cacheHitRate" style="color:var(--accent-emerald);">0.0%</b>
        </span>
        <span style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <span>累计解析服务数:</span> <b id="totalRequests" style="color:var(--text);">0</b>
        </span>
        <span id="uptimeWrap" style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>实例运行时间:</span> <b id="nodeUptime" style="color:var(--text);">0s</b>
        </span>
        <span style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>
          <span>Analytics Engine:</span> <b id="analyticsStatus" style="color:var(--primary);">已接入 (Worker 点位写入)</b>
        </span>
      </div>
    </section>

    <!-- 全平台客户端接入指南 -->
    <section class="card" style="margin-bottom: 32px;">
      <div class="card-header">
        <div class="card-title">
          <span class="card-title-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>
          </span>
          <span>全平台客户端接入指南</span>
        </div>
        <span style="font-size:0.8rem; color:var(--text-muted);">一键复制配置</span>
      </div>

      <div class="tabs-header">
        <button class="tab-btn active" onclick="switchClientTab('mihomo')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/></svg>
          <span>Clash / Mihomo</span>
        </button>
        <button class="tab-btn" onclick="switchClientTab('surge')">Surge</button>
        <button class="tab-btn" onclick="switchClientTab('singbox')">Sing-box</button>
        <button class="tab-btn" onclick="switchClientTab('shadowrocket')">Shadowrocket</button>
        <button class="tab-btn" onclick="switchClientTab('android')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="4" width="10" height="16" rx="2"/><line x1="11" y1="17" x2="13" y2="17"/></svg>
          <span>Android (私人 DNS)</span>
        </button>
        <button class="tab-btn" onclick="switchClientTab('windows')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>
          <span>Windows 11 / dnscrypt</span>
        </button>
        <button class="tab-btn" onclick="switchClientTab('apple')">iOS / macOS</button>
        <button class="tab-btn" onclick="switchClientTab('linux')">Linux (resolved)</button>
        <button class="tab-btn" onclick="switchClientTab('cli')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          <span>cURL / dig 调试</span>
        </button>
      </div>

      <!-- Tab Mihomo / Clash -->
      <div id="tab-mihomo" class="client-tab-content">
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:10px;">
          适用于 Mihomo (Clash Verge Rev / Mihomo Party / ShellCrash)。注意 <code>default-nameserver</code> 必须为纯 IP 以防死循环。
        </div>
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-mihomo')">复制代码</button>
          <pre id="code-mihomo"><code>dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  nameserver:
    - "${origin}${config.path}"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  proxy-server-nameserver:
    - 223.5.5.5
  nameserver-policy:
    "doh.mangoqwq.com":
      - 223.5.5.5</code></pre>
        </div>
      </div>

      <!-- Tab Surge -->
      <div id="tab-surge" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-surge')">复制代码</button>
          <pre id="code-surge"><code>[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = ${origin}${config.path}
doh-format = wire</code></pre>
        </div>
      </div>

      <!-- Tab Sing-box -->
      <div id="tab-singbox" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-singbox')">复制代码</button>
          <pre id="code-singbox"><code>{
  "dns": {
    "servers": [
      {
        "tag": "cf-doh",
        "address": "${origin}${config.path}",
        "detour": "direct"
      },
      {
        "tag": "local-bootstrap",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "domain": ["doh.mangoqwq.com"],
        "server": "local-bootstrap"
      }
    ],
    "strategy": "prefer_ipv4"
  }
}</code></pre>
        </div>
      </div>

      <!-- Tab Shadowrocket -->
      <div id="tab-shadowrocket" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-shadowrocket')">复制代码</button>
          <pre id="code-shadowrocket"><code># 1. 打开 Shadowrocket -> 设置 -> DNS
# 2. 启用「DNS-over-HTTPS」
# 3. 在 DNS 服务器 URL 填入：
${origin}${config.path}</code></pre>
        </div>
      </div>

      <!-- Tab Android -->
      <div id="tab-android" class="client-tab-content" style="display:none;">
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:10px;">
          推荐方式一（RFC 7858 DoT）：系统底层全局生效、零耗电、防污染。
        </div>
        <div class="code-block">
          <button class="copy-btn" onclick="copyText('2fa.mangoqwq.com')">复制主机名</button>
          <pre><code># 方式一：系统级私人 DNS (Android 9+ / 推荐)
设置 -> 连接与共享 / 网络和互联网 -> 私人 DNS (Private DNS) -> 选择「指定主机名」：
2fa.mangoqwq.com

# 方式二：Chrome / Edge 等浏览器端安全 DNS (DoH)
设置 -> 隐私和安全性 -> 使用安全 DNS -> 选择提供商 -> 自定义：
${origin}${config.path}</code></pre>
        </div>
      </div>

      <!-- Tab Windows -->
      <div id="tab-windows" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-win')">复制代码</button>
          <pre id="code-win"><code># 方案 A：Windows 11 原生安全 DNS (加密通过 HTTPS)
# 设置 -> 网络和 Internet -> 属性 -> DNS 服务器分配 (手动) -> 启用「仅加密」
DoH 模板 URL:
${origin}${config.path}

# 方案 B：dnscrypt-proxy (自建无缝守护)
# Stamp (sdns):
sdns://AgEAAAAAAAAAAAAQZG9oLm1hbmdvcXdxLmNvbQQvZG9o</code></pre>
        </div>
      </div>

      <!-- Tab Apple -->
      <div id="tab-apple" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-apple')">复制代码</button>
          <pre id="code-apple"><code># iOS 14+ / macOS 11+ 原生支持 DoH 描述文件 (.mobileconfig)
# 对应 DoH 服务器地址:
${origin}${config.path}

# 亦可在 Safari / 浏览器中作为安全 DNS 提供商配置。</code></pre>
        </div>
      </div>

      <!-- Tab Linux -->
      <div id="tab-linux" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-linux')">复制代码</button>
          <pre id="code-linux"><code># Linux 生产接入最佳实践 (dnscrypt-proxy 本地环回 + systemd-resolved)
# /etc/systemd/resolved.conf.d/doh.conf:
[Resolve]
DNS=127.0.0.1:5053
Domains=~.

# dnscrypt-proxy 监听 127.0.0.1:5053 并使用 Stamp：
sdns://AgEAAAAAAAAAAAAQZG9oLm1hbmdvcXdxLmNvbQQvZG9o</code></pre>
        </div>
      </div>

      <!-- Tab CLI -->
      <div id="tab-cli" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-cli')">复制代码</button>
          <pre id="code-cli"><code># 1. 服务健康探测与当前版本
curl -s "${origin}/healthz"

# 2. 通过 JSON API 快速解析 A 记录
curl -s "${origin}${config.jsonPath}?name=linux.do&type=A"

# 3. kdig (knot-dnsutils) 标准 RFC 8484 查询
kdig -d @${new URL(origin).hostname} +https=${config.path} linux.do A

# 4. doggo 命令行工具测试
doggo linux.do @${origin}${config.path} --doh</code></pre>
        </div>
      </div>
    </section>

    <!-- 架构与核心优势网格 -->
    <section class="card">
      <div class="card-header">
        <div class="card-title">
          <span class="card-title-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/></svg>
          </span>
          <span>核心架构与技术保障</span>
        </div>
        <span style="font-size:0.8rem; color:var(--text-muted);">为什么选择 cf-doh？</span>
      </div>

      <div class="grid grid-2" style="margin-bottom:0;">
        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">全并发竞价 (Zero Wait Racing)</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              国内组与全球组同组所有上游并发 fan-out 发起查询，响应时间取最快上游首包，慢上游自动 Abort，彻底告别单点超时卡顿。
            </p>
          </div>
        </div>

        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">可信真实 ECS 注入</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              严格基于 Cloudflare 边缘可信报头注入 IPv4 /24 与 IPv6 /56 客户端子网，杜绝伪造 XFF 欺骗，引导权威 CDN 精准就近调度。
            </p>
          </div>
        </div>

        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">防污染硬隔离与规则自愈</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              内置 linux.do 与 github.com 直连硬编码保护。外部规则集解析异常或网络中断时自动冷却降级，确保核心基础服务永不掉线。
            </p>
          </div>
        </div>

        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m14 5h5v5M19 5l-8 8M19 14v3a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h3"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">零外部依赖 & 毫秒级冷启</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              纯原生 JavaScript ESM 实现，零重量级框架侵入，无论是免费版还是企业版 Cloudflare Workers，单文件 bundle 均可秒级启动。
            </p>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Footer -->
  <footer>
    <div class="footer-links">
      <a href="https://github.com/dengyie/cf-doh" target="_blank" rel="noopener">
        <span>GitHub 源码仓库</span>
      </a>
      <span>•</span>
      <a href="${origin}/healthz" target="_blank" rel="noopener">服务健康探针 (/healthz)</a>
      <span>•</span>
      <a href="${origin}/api/stats" target="_blank" rel="noopener">实时度量 API (/api/stats)</a>
    </div>
    <p style="font-size:0.82rem; color:var(--text-faint);">
      cf-doh • 基于 MIT License 开源 • Powered by Cloudflare Workers & Serverless Edge Computing
    </p>
  </footer>

  <!-- Toast Element -->
  <div id="toast" class="toast">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 4 4L19 6"/></svg>
    <span id="toastMsg">已复制</span>
  </div>

  <!-- Client-side Logic & Web Components -->
  <script>
    // ---- Web Component: <theme-toggle> --------------------------------------
    class ThemeToggle extends HTMLElement {
      connectedCallback() {
        this.storageKey = this.getAttribute('storage-key') || 'cf-doh-theme';
        this.mode = localStorage.getItem(this.storageKey) || 'auto';
        this.render();
        this.applyTheme(this.mode, false);
        this.bindEvents();
      }
      resolveTheme(m) {
        if (m === 'light' || m === 'dark') return m;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      applyTheme(nextMode, notify = true) {
        this.mode = nextMode;
        var resolved = this.resolveTheme(nextMode);
        document.documentElement.dataset.theme = nextMode;
        document.documentElement.dataset.resolvedTheme = resolved;
        if (resolved === 'dark') {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
        localStorage.setItem(this.storageKey, nextMode);
        this.updateActiveButtons();
      }
      updateActiveButtons() {
        var btns = this.querySelectorAll('[data-mode]');
        for (var i = 0; i < btns.length; i++) {
          var btn = btns[i];
          if (btn.dataset.mode === this.mode) {
            btn.style.background = 'var(--card-bg)';
            btn.style.color = 'var(--primary)';
            btn.style.fontWeight = '600';
            btn.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
          } else {
            btn.style.background = 'transparent';
            btn.style.color = 'var(--text-muted)';
            btn.style.fontWeight = 'normal';
            btn.style.boxShadow = 'none';
          }
        }
      }
      render() {
        this.innerHTML =
          '<div style="display:inline-flex; align-items:center; padding:2px; border-radius:10px; background:var(--code-bg); border:1px solid var(--card-border); font-size:0.78rem;">' +
            '<button type="button" data-mode="auto" title="跟随系统" aria-label="跟随系统" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:7px; border:none; cursor:pointer; transition:all 0.15s;">' +
              '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>' +
              '<span>Auto</span>' +
            '</button>' +
            '<button type="button" data-mode="light" title="亮色模式" aria-label="亮色模式" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:7px; border:none; cursor:pointer; transition:all 0.15s;">' +
              '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2"/></svg>' +
              '<span>Light</span>' +
            '</button>' +
            '<button type="button" data-mode="dark" title="暗色模式" aria-label="暗色模式" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:7px; border:none; cursor:pointer; transition:all 0.15s;">' +
              '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 15.5A8 8 0 0 1 8.5 4 8 8 0 0 0 20 15.5Z"/></svg>' +
              '<span>Dark</span>' +
            '</button>' +
          '</div>';
      }
      bindEvents() {
        var self = this;
        this.addEventListener('click', function(e) {
          var btn = e.target.closest('[data-mode]');
          if (btn) {
            self.applyTheme(btn.dataset.mode);
          }
        });
      }
    }
    if (!customElements.get('theme-toggle')) {
      customElements.define('theme-toggle', ThemeToggle);
    }

    // ---- Web Component: <status-indicator> -----------------------------------
    class StatusIndicator extends HTMLElement {
      static get observedAttributes() { return ['status', 'label', 'ping-ms', 'show-dot']; }
      connectedCallback() { this.render(); }
      attributeChangedCallback() { this.render(); }
      render() {
        var status = this.getAttribute('status') || 'online';
        var label = this.getAttribute('label') || '在线';
        var pingMs = this.getAttribute('ping-ms');
        var showDot = this.getAttribute('show-dot') !== 'false';

        var dotColor = '#10b981', bg = 'rgba(16, 185, 129, 0.12)', text = '#10b981', border = 'rgba(16, 185, 129, 0.25)';
        if (status === 'connecting' || status === 'busy') {
          dotColor = '#f59e0b'; bg = 'rgba(245, 158, 11, 0.12)'; text = '#f59e0b'; border = 'rgba(245, 158, 11, 0.25)';
        } else if (status === 'error' || status === 'offline') {
          dotColor = '#ef4444'; bg = 'rgba(239, 68, 68, 0.12)'; text = '#ef4444'; border = 'rgba(239, 68, 68, 0.25)';
        }

        var dotHtml = '';
        if (showDot) {
          var pingPulse = status === 'online' ? '<span style="position:absolute; width:100%; height:100%; border-radius:50%; background:' + dotColor + '; opacity:0.6; animation:ping 1.4s cubic-bezier(0, 0, 0.2, 1) infinite;"></span>' : '';
          dotHtml = '<span style="position:relative; display:inline-flex; width:7px; height:7px;">' +
            pingPulse +
            '<span style="position:relative; width:7px; height:7px; border-radius:50%; background:' + dotColor + ';"></span>' +
          '</span>';
        }

        var pingText = (pingMs !== null && pingMs !== undefined && pingMs !== '') ? '<span style="opacity:0.8; font-family:monospace; font-size:0.72rem;">(' + pingMs + 'ms)</span>' : '';

        this.innerHTML =
          '<div style="display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:9999px; background:' + bg + '; border:1px solid ' + border + '; color:' + text + '; font-size:0.76rem; font-weight:600;">' +
            dotHtml +
            '<span class="status-indicator-label">' + label + '</span>' +
            pingText +
          '</div>';
      }
    }
    if (!customElements.get('status-indicator')) {
      customElements.define('status-indicator', StatusIndicator);
    }

    // Ping animation keyframe
    var styleSheet = document.createElement("style");
    styleSheet.innerText = "@keyframes ping { 75%, 100% { transform: scale(2.2); opacity: 0; } }";
    document.head.appendChild(styleSheet);

    // ---- Utilities & State --------------------------------------------------
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/[&<>"']/g, function(m) {
        switch (m) {
          case '&': return '&amp;';
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '"': return '&quot;';
          case "'": return '&#39;';
          default: return m;
        }
      });
    }

    function showToast(msg) {
      var toast = document.getElementById('toast');
      var toastMsg = document.getElementById('toastMsg');
      toastMsg.innerText = msg;
      toast.classList.add('show');
      setTimeout(function() { toast.classList.remove('show'); }, 2200);
    }

    function copyText(txt) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function() {
          showToast('已复制到剪贴板');
        }).catch(function() {
          legacyCopy(txt);
        });
      } else {
        legacyCopy(txt);
      }
    }

    function legacyCopy(txt) {
      var input = document.createElement('textarea');
      input.value = txt;
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      document.body.removeChild(input);
      showToast('已复制到剪贴板');
    }

    function copyElement(id) {
      var el = document.getElementById(id);
      if (el) copyText(el.innerText);
    }

    // ---- Playground Query ---------------------------------------------------
    var lastQueryResult = null;
    var currentResultView = 'formatted';

    function setQuery(domain, type) {
      document.getElementById('domainInput').value = domain;
      if (type) document.getElementById('typeSelect').value = type;
      runQuery();
    }

    function switchResultView(view) {
      currentResultView = view;
      var fmtBtn = document.getElementById('viewFormattedBtn');
      var rawBtn = document.getElementById('viewRawBtn');
      if (view === 'formatted') {
        fmtBtn.classList.add('active');
        rawBtn.classList.remove('active');
      } else {
        rawBtn.classList.add('active');
        fmtBtn.classList.remove('active');
      }
      renderQueryResult();
    }

    async function runQuery() {
      var domain = document.getElementById('domainInput').value.trim();
      var type = document.getElementById('typeSelect').value;
      var box = document.getElementById('playgroundResult');
      var btn = document.getElementById('queryBtn');
      if (!domain) return;

      btn.disabled = true;
      btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>查询中...</span>';

      var start = performance.now();
      try {
        var resp = await fetch('${config.jsonPath}?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
        var data = await resp.json();
        var duration = Math.round(performance.now() - start);

        lastQueryResult = {
          domain: domain,
          type: type,
          data: data,
          duration: duration,
          status: resp.status
        };
        renderQueryResult();
        loadStats();
      } catch (err) {
        box.innerHTML = '<div style="color:var(--accent-rose); font-size:0.88rem; padding:12px;">' +
          '<strong>查询失败：</strong> ' + escapeHtml(err.message) +
          '</div>';
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="7"/><line x1="21" y1="21" x2="15" y2="15"/></svg><span>查询</span>';
      }
    }

    function renderQueryResult() {
      var box = document.getElementById('playgroundResult');
      if (!lastQueryResult) return;
      var q = lastQueryResult;
      var data = q.data;

      if (currentResultView === 'raw') {
        box.innerHTML = '<div style="position:relative;">' +
          '<button class="copy-btn" onclick="copyText(document.getElementById(\\'rawJsonBlock\\').innerText)">复制 JSON</button>' +
          '<pre id="rawJsonBlock" style="margin:0; font-family:ui-monospace, monospace; font-size:0.82rem; color:var(--text); max-height:360px; overflow-y:auto;">' +
          escapeHtml(JSON.stringify(data, null, 2)) +
          '</pre></div>';
        return;
      }

      var statusNum = Number(data.Status);
      var statusBadge = '';
      if (statusNum === 0) {
        statusBadge = '<span class="meta-badge success">● NOERROR (成功)</span>';
      } else if (statusNum === 3) {
        statusBadge = '<span class="meta-badge warn">● NXDOMAIN (域名不存在)</span>';
      } else {
        statusBadge = '<span class="meta-badge error">● Status ' + statusNum + '</span>';
      }

      var dnssecBadge = data.AD
        ? '<span class="meta-badge info"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg> DNSSEC 已验证 (AD=1)</span>'
        : '<span class="meta-badge" style="color:var(--text-faint);">DNSSEC 未签名 (AD=0)</span>';

      var isDomestic = (q.domain.endsWith('linux.do') || q.domain.endsWith('github.com') || q.domain.endsWith('.cn') || q.domain.includes('bilibili') || q.domain.includes('ali') || q.domain.includes('tencent'));
      var routeGroupBadge = isDomestic
        ? '<span class="meta-badge info">分流：国内直连组</span>'
        : '<span class="meta-badge" style="color:var(--accent-purple); background:rgba(139,92,246,0.12); border-color:rgba(139,92,246,0.25);">分流：全球兜底组</span>';

      var html = '<div class="meta-badges">' +
        statusBadge +
        '<span class="meta-badge">链路耗时: <b style="color:var(--primary); margin-left:3px;">' + q.duration + ' ms</b></span>' +
        dnssecBadge +
        routeGroupBadge +
        '</div>';

      if (Array.isArray(data.Answer) && data.Answer.length > 0) {
        html += '<div style="font-size:0.82rem; font-weight:600; color:var(--text-muted); margin-bottom:6px;">应答解析记录 (Answers):</div>';
        html += '<table class="record-table"><thead><tr>' +
          '<th>Name</th><th>Type</th><th>TTL</th><th>Data (Resolved)</th><th></th>' +
          '</tr></thead><tbody>';
        data.Answer.forEach(function(ans, idx) {
          var safeName = escapeHtml(ans.name);
          var safeType = escapeHtml(ans.type);
          var safeData = escapeHtml(ans.data);
          var safeTtl = Number(ans.TTL) || 0;
          html += '<tr>' +
            '<td>' + safeName + '</td>' +
            '<td><span class="record-type-pill">' + safeType + '</span></td>' +
            '<td style="color:var(--text-faint);">' + safeTtl + 's</td>' +
            '<td style="font-weight:600; color:var(--text);">' + safeData + '</td>' +
            '<td style="text-align:right;"><button class="btn btn-secondary" style="padding:2px 8px; font-size:0.75rem;" onclick="copyText(\\'' + safeData.replace(/'/g, "\\\\'") + '\\')">复制值</button></td>' +
            '</tr>';
        });
        html += '</tbody></table>';
      } else {
        html += '<div style="color:var(--text-muted); font-size:0.85rem; padding:8px 0;">未查询到对应应答记录 (ANCOUNT=0)。</div>';
      }

      if (Array.isArray(data.Authority) && data.Authority.length > 0) {
        html += '<details style="margin-top:12px; font-size:0.82rem; color:var(--text-muted);">' +
          '<summary style="cursor:pointer; font-weight:600; padding:4px 0;">查看权威记录 (Authority: ' + data.Authority.length + ' 条)</summary>' +
          '<div style="margin-top:6px; background:rgba(0,0,0,0.15); padding:8px; border-radius:6px; font-family:ui-monospace, monospace;">';
        data.Authority.forEach(function(auth) {
          html += '<div>' + escapeHtml(auth.name) + ' ' + escapeHtml(auth.type) + ' ' + escapeHtml(auth.data) + '</div>';
        });
        html += '</div></details>';
      }

      box.innerHTML = html;
    }

    // ---- Racing Telemetry & Stats -------------------------------------------
    var currentScope = 'local';
    var autoRefreshTimer = null;

    function setStatsScope(scope) {
      currentScope = scope;
      var localBtn = document.getElementById('scopeLocalBtn');
      var globalBtn = document.getElementById('scopeGlobalBtn');
      if (scope === 'global') {
        localBtn.classList.remove('active');
        globalBtn.classList.add('active');
      } else {
        globalBtn.classList.remove('active');
        localBtn.classList.add('active');
      }
      loadStats(scope);
    }

    function toggleAutoRefresh(enable) {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      if (enable) {
        autoRefreshTimer = setInterval(function() {
          loadStats(currentScope);
        }, 10000);
      }
    }

    async function loadStats(scope = currentScope) {
      var icon = document.getElementById('refreshIcon');
      if (icon) icon.style.animation = 'spin 1s linear infinite';
      try {
        var url = scope === 'global' ? '/api/stats?scope=global' : '/api/stats';
        var resp = await fetch(url);
        if (!resp.ok) return;
        var rawData = await resp.json();
        var isGlobal = scope === 'global';
        var noticeEl = document.getElementById('scopeNotice');

        var data = rawData;
        if (isGlobal) {
          if (rawData.available) {
            noticeEl.innerHTML = '<b>全球多地域聚合数据 (Cloudflare Analytics Engine)</b> · 最近 24 小时跨所有 PoP 边缘节点总计';
            noticeEl.style.borderLeftColor = 'var(--accent-emerald)';
            document.getElementById('analyticsStatus').innerText = '全局 SQL 查询已激活';
            document.getElementById('analyticsStatus').style.color = 'var(--accent-emerald)';
            document.getElementById('uptimeWrap').style.display = 'none';
          } else {
            noticeEl.innerHTML = '<b>全球聚合未开启或未配置读取凭据</b>：' + escapeHtml(rawData.message || '回退展示当前本地 PoP 数据') + '。可至 Cloudflare 控制台激活 Analytics Engine。';
            noticeEl.style.borderLeftColor = 'var(--accent-amber)';
            document.getElementById('analyticsStatus').innerText = '未激活全局读取 (展示本地)';
            document.getElementById('analyticsStatus').style.color = 'var(--accent-amber)';
            document.getElementById('uptimeWrap').style.display = 'inline-flex';
            if (rawData.fallback) data = rawData.fallback;
          }
        } else {
          noticeEl.innerHTML = '统计范围：当前 Cloudflare 边缘节点内存实时采样 (单实例)';
          noticeEl.style.borderLeftColor = 'var(--primary)';
          document.getElementById('analyticsStatus').innerText = '已接入 (Worker 点位写入)';
          document.getElementById('analyticsStatus').style.color = 'var(--primary)';
          document.getElementById('uptimeWrap').style.display = 'inline-flex';
        }

        // Domestic
        var dom = (data.upstreams && data.upstreams.domestic) ? data.upstreams.domestic : { upstreams: {}, totalWins: 0 };
        var ali = dom.upstreams['dns.alidns.com'] || { wins: 0, winRate: '0.0%' };
        var pod = dom.upstreams['doh.pub'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('domesticTotalWins').innerText = dom.totalWins + ' 次胜出';
        document.getElementById('winAlidns').innerText = ali.wins + ' (' + ali.winRate + ')';
        document.getElementById('winDohpub').innerText = pod.wins + ' (' + pod.winRate + ')';
        var domTotal = ali.wins + pod.wins;
        var aliPct = domTotal > 0 ? (ali.wins / domTotal) * 100 : 50;
        document.getElementById('barAlidns').style.width = aliPct + '%';
        document.getElementById('barDohpub').style.width = (100 - aliPct) + '%';

        if (data.latency && data.latency.domestic) {
          document.getElementById('p50Domestic').innerText = (data.latency.domestic.p50Ms || 0) + ' ms';
          document.getElementById('p95Domestic').innerText = (data.latency.domestic.p95Ms || 0) + ' ms';
          document.getElementById('avgDomestic').innerText = (data.latency.domestic.avgMs || 0) + ' ms';
        }

        // Global
        var glob = (data.upstreams && data.upstreams.global) ? data.upstreams.global : { upstreams: {}, totalWins: 0 };
        var ggl = glob.upstreams['dns.google'] || { wins: 0, winRate: '0.0%' };
        var cf = glob.upstreams['cloudflare-dns.com'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('globalTotalWins').innerText = glob.totalWins + ' 次胜出';
        document.getElementById('winGoogle').innerText = ggl.wins + ' (' + ggl.winRate + ')';
        document.getElementById('winCf').innerText = cf.wins + ' (' + cf.winRate + ')';
        var globTotal = ggl.wins + cf.wins;
        var gglPct = globTotal > 0 ? (ggl.wins / globTotal) * 100 : 50;
        document.getElementById('barGoogle').style.width = gglPct + '%';
        document.getElementById('barCf').style.width = (100 - gglPct) + '%';

        if (data.latency && data.latency.global) {
          document.getElementById('p50Global').innerText = (data.latency.global.p50Ms || 0) + ' ms';
          document.getElementById('p95Global').innerText = (data.latency.global.p95Ms || 0) + ' ms';
          document.getElementById('avgGlobal').innerText = (data.latency.global.avgMs || 0) + ' ms';
        }

        if (data.cache) {
          document.getElementById('cacheHitRate').innerText = data.cache.hitRate || '0.0%';
        }
        if (typeof data.totalRequests !== 'undefined') {
          document.getElementById('totalRequests').innerText = data.totalRequests;
        }
        if (typeof data.uptimeSec !== 'undefined') {
          document.getElementById('nodeUptime').innerText = formatUptime(data.uptimeSec);
        }
      } catch (err) {
        console.warn('Failed to load stats:', err);
      } finally {
        if (icon) setTimeout(function() { icon.style.animation = ''; }, 300);
      }
    }

    function formatUptime(sec) {
      if (!sec || sec < 0) return '0s';
      if (sec < 60) return sec + 's';
      if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
      var h = Math.floor(sec / 3600);
      var m = Math.floor((sec % 3600) / 60);
      return h + 'h ' + m + 'm';
    }

    // Gateway Live Probe (/healthz)
    async function probeGateway() {
      var indicator = document.getElementById('globalGatewayStatus');
      var start = performance.now();
      try {
        var resp = await fetch('/healthz');
        var duration = Math.round(performance.now() - start);
        if (resp.ok) {
          var data = await resp.json();
          indicator.setAttribute('status', 'online');
          indicator.setAttribute('label', '边缘在线 (' + (data.version || 'v1.2.0') + ')');
          indicator.setAttribute('ping-ms', duration);
        } else {
          indicator.setAttribute('status', 'error');
          indicator.setAttribute('label', '状态异常');
        }
      } catch (e) {
        indicator.setAttribute('status', 'offline');
        indicator.setAttribute('label', '探测离线');
      }
    }

    // Client Config Tabs
    function switchClientTab(name) {
      var contents = document.querySelectorAll('.client-tab-content');
      for (var i = 0; i < contents.length; i++) contents[i].style.display = 'none';
      var btns = document.querySelectorAll('.tabs-header .tab-btn');
      for (var j = 0; j < btns.length; j++) btns[j].classList.remove('active');

      var target = document.getElementById('tab-' + name);
      if (target) target.style.display = 'block';
      if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
      }
    }

    // Init
    window.addEventListener('DOMContentLoaded', function() {
      loadStats();
      probeGateway();
      toggleAutoRefresh(true);
      setInterval(probeGateway, 30000);
    });
  </script>
</body>
</html>`;
}
