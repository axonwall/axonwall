/**
 * NastyMap Standalone Exporter
 * Generates Headless SVG Vector Maps and Standalone HTML Reports.
 */

function escapeXml(unsafe) {
  if (unsafe === undefined || unsafe === null) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function coerceSvgNumber(value, fallback) {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : fallback;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return fallback;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : fallback;
  }
  return fallback;
}

function coercePositiveSvgNumber(value, fallback) {
  const num = coerceSvgNumber(value, fallback);
  return num > 0 ? num : fallback;
}

function sanitizeSvgColor(value, fallback) {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  if (
    /^#[0-9a-f]{3,8}$/i.test(trimmed) ||
    /^[a-z]{1,24}$/i.test(trimmed) ||
    /^(rgb|hsl)a?\(\s*[0-9.%\s,]+\)$/i.test(trimmed)
  ) {
    return escapeXml(trimmed);
  }
  return fallback;
}

/**
 * Generates an SVG string representation of a TopologyGraph without requiring a DOM.
 * @param {Object} graph TopologyGraph { nodes: [], links: [] }
 * @param {Object} [options]
 * @returns {string} SVG XML content
 */
export function generateHeadlessSvg(graph, options = {}) {
  const opts = options ?? {};
  const width = coercePositiveSvgNumber(opts.width, 1200);
  const height = coercePositiveSvgNumber(opts.height, 800);
  const title = escapeXml(opts.title || 'Nmap Network Topology Map');
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const links = Array.isArray(graph?.links) ? graph.links : [];

  const nodeMap = new Map();
  for (const n of nodes) nodeMap.set(n.id, n);

  let linksSvg = '';
  for (const link of links) {
    const sId = typeof link.source === 'string' ? link.source : link.source?.id;
    const tId = typeof link.target === 'string' ? link.target : link.target?.id;
    const s = nodeMap.get(sId);
    const t = nodeMap.get(tId);
    if (!s || !t) continue;

    let strokeColor = link.type === 'traceroute' ? '#38bdf8' : '#64748b';
    let strokeWidth = link.type === 'traceroute' ? 2 : 1.5;
    let strokeDash = link.type === 'subnet' ? 'stroke-dasharray="4,4"' : '';

    if (link.type === 'lateral-attack-path') {
      strokeColor = '#ef4444';
      strokeWidth = 2.5;
      strokeDash = 'stroke-dasharray="6,3"';
    }

    const sx = coerceSvgNumber(s.x, 0);
    const sy = coerceSvgNumber(s.y, 0);
    const tx = coerceSvgNumber(t.x, 0);
    const ty = coerceSvgNumber(t.y, 0);
    const safeStrokeWidth = coercePositiveSvgNumber(strokeWidth, 1.5);
    const safeOpacity = coerceSvgNumber(0.8, 0.8);

    linksSvg += `
      <line x1="${escapeXml(sx)}" y1="${escapeXml(sy)}" x2="${escapeXml(tx)}" y2="${escapeXml(ty)}" stroke="${escapeXml(strokeColor)}" stroke-width="${escapeXml(safeStrokeWidth)}" ${strokeDash} opacity="${escapeXml(safeOpacity)}" />
    `;

    if (link.label) {
      const midX = coerceSvgNumber((sx + tx) / 2, 0);
      const midY = coerceSvgNumber((sy + ty) / 2, 0);
      const labelY = coerceSvgNumber(midY - 4, -4);
      const linkFontSize = coercePositiveSvgNumber(10, 10);
      const labelColor = link.type === 'lateral-attack-path' ? '#f87171' : '#94a3b8';
      linksSvg += `
        <text x="${escapeXml(midX)}" y="${escapeXml(labelY)}" fill="${escapeXml(labelColor)}" font-size="${escapeXml(linkFontSize)}" font-family="monospace" font-weight="${escapeXml(link.type === 'lateral-attack-path' ? 'bold' : 'normal')}" text-anchor="middle">${escapeXml(link.label)}</text>
      `;
    }
  }

  let nodesSvg = '';
  for (const node of nodes) {
    const isScanner = node.nodeType === 'scanner';
    const fill = sanitizeSvgColor(node.color, '#3b82f6');
    const stroke = escapeXml(isScanner ? '#a855f7' : node.riskTier === 'CRITICAL' ? '#ef4444' : node.status === 'up' ? '#22c55e' : '#ef4444');
    const nx = coerceSvgNumber(node.x, 0);
    const ny = coerceSvgNumber(node.y, 0);
    const r = coercePositiveSvgNumber(node.radius, 10);
    const nodeStrokeWidth = coercePositiveSvgNumber(node.riskTier === 'CRITICAL' ? 3.5 : 2.5, 2.5);
    const labelY = coerceSvgNumber(r + 14, 24);
    const ipY = coerceSvgNumber(r + 26, 36);
    const riskY = coerceSvgNumber(r + 38, 48);
    const labelFontSize = coercePositiveSvgNumber(11, 11);
    const ipFontSize = coercePositiveSvgNumber(9, 9);
    const riskFontSize = coercePositiveSvgNumber(9, 9);

    const hasRiskScore = typeof node.riskScore === 'number' && Number.isFinite(node.riskScore);
    const riskScoreVal = hasRiskScore ? coerceSvgNumber(node.riskScore, 0) : 0;
    const riskColor = node.riskTier === 'CRITICAL' ? '#f87171' : node.riskTier === 'HIGH' ? '#fbbf24' : '#22c55e';
    const riskBadge = hasRiskScore
      ? `<text y="${escapeXml(riskY)}" fill="${escapeXml(riskColor)}" font-size="${escapeXml(riskFontSize)}" font-family="monospace" font-weight="bold" text-anchor="middle">RISK: ${escapeXml(riskScoreVal)}/100 [${escapeXml(node.riskTier || 'CLEAN')}]</text>`
      : '';

    nodesSvg += `
      <g transform="translate(${escapeXml(nx)}, ${escapeXml(ny)})">
        <circle r="${escapeXml(r)}" fill="${fill}" stroke="${stroke}" stroke-width="${escapeXml(nodeStrokeWidth)}" />
        <text y="${escapeXml(labelY)}" fill="#f8fafc" font-size="${escapeXml(labelFontSize)}" font-family="system-ui, sans-serif" font-weight="600" text-anchor="middle">${escapeXml(node.label)}</text>
        <text y="${escapeXml(ipY)}" fill="#94a3b8" font-size="${escapeXml(ipFontSize)}" font-family="monospace" text-anchor="middle">${escapeXml(node.ip)}</text>
        ${riskBadge}
      </g>
    `;
  }

  const bgCx = coerceSvgNumber(width / 2, 600);
  const bgCy = coerceSvgNumber(height / 2, 400);
  const bgR = coercePositiveSvgNumber(Math.min(width, height) * 0.45, 360);
  const titleX = coerceSvgNumber(24, 24);
  const titleY = coerceSvgNumber(36, 36);
  const titleFontSize = coercePositiveSvgNumber(18, 18);
  const subtitleY = coerceSvgNumber(56, 56);
  const subtitleFontSize = coercePositiveSvgNumber(12, 12);
  const nodeCount = coerceSvgNumber(nodes.length, 0);
  const linkCount = coerceSvgNumber(links.length, 0);

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${escapeXml(width)} ${escapeXml(height)}" width="${escapeXml(width)}" height="${escapeXml(height)}" style="background-color: #0b0f19;">
  <defs>
    <radialGradient id="bgGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#1e1b4b" stop-opacity="0.5" />
      <stop offset="100%" stop-color="#0b0f19" stop-opacity="0" />
    </radialGradient>
  </defs>
  <rect width="100%" height="100%" fill="#0b0f19" />
  <circle cx="${escapeXml(bgCx)}" cy="${escapeXml(bgCy)}" r="${escapeXml(bgR)}" fill="url(#bgGlow)" />
  
  <text x="${escapeXml(titleX)}" y="${escapeXml(titleY)}" fill="#f8fafc" font-size="${escapeXml(titleFontSize)}" font-family="system-ui, sans-serif" font-weight="bold">${title}</text>
  <text x="${escapeXml(titleX)}" y="${escapeXml(subtitleY)}" fill="#64748b" font-size="${escapeXml(subtitleFontSize)}" font-family="monospace">Generated with NastyMap · ${escapeXml(nodeCount)} nodes · ${escapeXml(linkCount)} links</text>

  <g id="links">
    ${linksSvg}
  </g>
  <g id="nodes">
    ${nodesSvg}
  </g>
</svg>`;
}

/**
 * Generate a standalone, self-contained HTML report with interactive styling, SVG topology, and host table.
 * @param {Object} scan Structured NmapRun object
 * @param {Object} graph TopologyGraph
 * @returns {string} Standalone HTML document
 */
export function generateHtmlReport(scan, graph) {
  const svgContent = generateHeadlessSvg(graph, {
    title: `Nmap Scan Topology: ${scan.args || scan.target || 'Network Scan'}`
  });

  const hostsList = (scan.hosts || [])
    .map((h) => {
      const isUp = h.status?.state === 'up' || h.isUp;
      const statusBadge = isUp
        ? '<span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: #065f46; color: #34d399;">UP</span>'
        : '<span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: #881337; color: #f87171;">DOWN</span>';

      const openPorts = (h.ports || [])
        .filter((p) => p.state === 'open')
        .map((p) => {
          const sName = p.service?.product
            ? ` (${escapeXml(p.service.product)}${p.service.version ? ' ' + escapeXml(p.service.version) : ''})`
            : p.service?.name
              ? ` (${escapeXml(p.service.name)})`
              : '';
          return `${escapeXml(p.portid || p.port)}/${escapeXml(p.protocol)}${sName}`;
        })
        .join(', ');

      const vulnCount = coerceSvgNumber(h.vulnerabilitiesCount, 0);
      const vulnBadge = vulnCount > 0
        ? `<span style="color:#ef4444; font-weight:bold;">⚠️ ${escapeXml(vulnCount)} CVE/Vuln</span>`
        : '<span style="color:#64748b;">-</span>';

      return `
      <tr style="border-bottom: 1px solid #1e293b;">
        <td style="padding: 10px 14px; font-family: monospace; color: #38bdf8; font-weight: bold;">${escapeXml(h.ipv4 || h.id)}</td>
        <td style="padding: 10px 14px; color: #f8fafc;">${escapeXml(h.primaryHostname || '-')}</td>
        <td style="padding: 10px 14px;">${statusBadge}</td>
        <td style="padding: 10px 14px; color: #94a3b8;">${escapeXml(h.primaryOs || h.osFamily || 'Unknown')}</td>
        <td style="padding: 10px 14px; color: #cbd5e1; font-family: monospace;">${openPorts || '<span style="color:#64748b;">None</span>'}</td>
        <td style="padding: 10px 14px;">${vulnBadge}</td>
        <td style="padding: 10px 14px; color: #94a3b8;">${h.latencyMs !== undefined ? `${escapeXml(h.latencyMs)} ms` : '-'}</td>
      </tr>
      `;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NastyMap - Security Topology & Network Scan Report</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1e293b;
      --primary: #38bdf8;
      --accent: #818cf8;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    body {
      margin: 0;
      padding: 28px;
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
    }
    .container {
      max-width: 1280px;
      margin: 0 auto;
    }
    .header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .stat-val {
      font-size: 24px;
      font-weight: bold;
      color: var(--primary);
    }
    .stat-label {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .map-container {
      margin: 24px 0;
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      background: #030712;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .map-container svg {
      width: 100%;
      height: auto;
      display: block;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th {
      background: #1e293b;
      padding: 12px 14px;
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
    }
    .table-container {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--card-bg);
    }
    .footer {
      margin-top: 32px;
      text-align: center;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid var(--border);
      padding-top: 16px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin: 0 0 6px 0; font-size: 26px; color: var(--primary);">🛡️ NastyMap Security Topology Report</h1>
        <p style="margin: 0; color: var(--muted); font-family: monospace; font-size: 13px;">Command: ${escapeXml(scan.args || scan.target || 'Nmap Network Scan')}</p>
        <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Scanned: ${escapeXml(scan.startstr || new Date().toISOString())} · Nmap v${escapeXml(scan.version || '7.x')} · File: ${escapeXml(scan.filename || 'active')}</p>
      </div>
      <div style="text-align: right;">
        <span style="display:inline-block; padding: 4px 12px; border-radius: 9999px; background: #1e1b4b; color: #a5b4fc; font-size: 12px; font-weight: bold; border: 1px solid #3730a3;">
          Vigilante + NastyMap Engine
        </span>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val">${escapeXml(coerceSvgNumber(scan?.hosts?.length, 0))}</div>
        <div class="stat-label">Total Hosts Discovered</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #22c55e;">${escapeXml(coerceSvgNumber(scan?.hosts?.filter(h => h.isUp || h.status?.state === 'up').length, 0))}</div>
        <div class="stat-label">Live Hosts (Up)</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #f59e0b;">${escapeXml((scan?.hosts || []).reduce((acc, h) => acc + coerceSvgNumber(h.openPortsCount, 0), 0))}</div>
        <div class="stat-label">Open Network Ports</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #ec4899;">${escapeXml(coerceSvgNumber(graph?.subnets?.length, 1))}</div>
        <div class="stat-label">Subnets Mapped</div>
      </div>
    </div>

    <h2 style="font-size: 18px; color: #f8fafc; margin: 28px 0 12px 0;">🌐 Interactive Network Topology</h2>
    <div class="map-container">
      ${svgContent}
    </div>

    <h2 style="font-size: 18px; color: #f8fafc; margin: 28px 0 12px 0;">📋 Discovered Hosts & Service Fingerprints</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>Status</th>
            <th>Operating System</th>
            <th>Open Ports & Services</th>
            <th>Vulnerabilities</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          ${hostsList}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Generated automatically by <strong>Vigilante Cyber Security Platform</strong> with <strong>NastyMap Engine</strong>.
    </div>
  </div>
</body>
</html>`;
}
