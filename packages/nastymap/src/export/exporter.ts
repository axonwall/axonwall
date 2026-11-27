import type { NmapRun, TopologyGraph } from '../types/nmap';

export interface ExportPngOptions {
  scale?: number;
  backgroundColor?: string;
  quality?: number;
}

/**
 * Trigger download of text or blob data in the browser.
 */
function downloadBlob(blob: Blob, filename: string): void {
  if (typeof window === 'undefined') return;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/**
 * Export an SVG element from the DOM to a downloadable .svg file.
 */
export function exportSvgElement(svgElement: SVGSVGElement, filename: string = 'nmap-topology.svg'): void {
  const serializer = new XMLSerializer();
  let source = serializer.serializeToString(svgElement);

  // Add namespaces if missing
  if (!source.match(/^<svg[^>]+xmlns="http:\/\/www\.w3\.org\/2000\/svg"/)) {
    source = source.replace(/^<svg/, '<svg xmlns="http://www.w3.org/2000/svg"');
  }
  if (!source.match(/^<svg[^>]+xmlns:xlink="http:\/\/www\.w3\.org\/1999\/xlink"/)) {
    source = source.replace(/^<svg/, '<svg xmlns:xlink="http://www.w3.org/1999/xlink"');
  }

  // Prepend XML declaration
  source = '<?xml version="1.0" standalone="no"?>\r\n' + source;

  const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
  downloadBlob(blob, filename);
}

/**
 * Export an SVG or Canvas element to a high-resolution PNG image file.
 */
export async function exportToPng(
  sourceElement: SVGSVGElement | HTMLCanvasElement,
  filename: string = 'nmap-topology.png',
  options: ExportPngOptions = {}
): Promise<void> {
  const scale = coercePositiveSvgNumber(options.scale, 2);
  const quality = coercePositiveSvgNumber(options.quality, 0.95);
  const bgColor = options.backgroundColor || '#090d16';

  if (sourceElement instanceof HTMLCanvasElement) {
    return new Promise((resolve, reject) => {
      sourceElement.toBlob((blob) => {
        if (blob) {
          downloadBlob(blob, filename);
          resolve();
        } else {
          reject(new Error('Canvas toBlob failed'));
        }
      }, 'image/png', quality);
    });
  }

  // If SVG element, render onto a canvas
  const bbox = sourceElement.getBoundingClientRect();
  const width = coercePositiveSvgNumber(bbox.width, 1200) * scale;
  const height = coercePositiveSvgNumber(bbox.height, 800) * scale;

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // Background
  ctx.fillStyle = bgColor;
  ctx.fillRect(0, 0, width, height);

  const serializer = new XMLSerializer();
  let svgString = serializer.serializeToString(sourceElement);
  if (!svgString.match(/^<svg[^>]+xmlns="http:\/\/www\.w3\.org\/2000\/svg"/)) {
    svgString = svgString.replace(/^<svg/, '<svg xmlns="http://www.w3.org/2000/svg"');
  }
  if (!svgString.match(/^<svg[^>]+xmlns:xlink="http:\/\/www\.w3\.org\/1999\/xlink"/)) {
    svgString = svgString.replace(/^<svg/, '<svg xmlns:xlink="http://www.w3.org/1999/xlink"');
  }
  const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(svgBlob);

  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      ctx.drawImage(img, 0, 0, width, height);
      URL.revokeObjectURL(url);
      canvas.toBlob((blob) => {
        if (blob) {
          downloadBlob(blob, filename);
          resolve();
        } else {
          reject(new Error('Canvas toBlob failed'));
        }
      }, 'image/png', quality);
    };
    img.onerror = (err) => {
      URL.revokeObjectURL(url);
      reject(err);
    };
    img.src = url;
  });
}

function escapeXml(unsafe: unknown): string {
  if (unsafe === undefined || unsafe === null) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function coerceSvgNumber(value: unknown, fallback: number): number {
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

function coercePositiveSvgNumber(value: unknown, fallback: number): number {
  const num = coerceSvgNumber(value, fallback);
  return num > 0 ? num : fallback;
}

function sanitizeSvgColor(value: unknown, fallback: string): string {
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
 * Programmatic headless generator: creates an SVG string representation of a TopologyGraph
 * without requiring a DOM (can run in Node.js / CLI / CI report generator).
 */
export function generateHeadlessSvg(
  graph: TopologyGraph,
  options: { width?: number; height?: number; title?: string } = {}
): string {
  const opts = options ?? {};
  const width = coercePositiveSvgNumber(opts.width, 1200);
  const height = coercePositiveSvgNumber(opts.height, 800);
  const title = opts.title || 'Nmap Network Topology Map';
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const links = Array.isArray(graph?.links) ? graph.links : [];

  const nodeMap = new Map<string, (typeof nodes)[number]>();
  for (const n of nodes) nodeMap.set(n.id, n);

  let linksSvg = '';
  for (const link of links) {
    const sId = typeof link.source === 'string' ? link.source : (link.source as any)?.id;
    const tId = typeof link.target === 'string' ? link.target : (link.target as any)?.id;
    const s = nodeMap.get(sId);
    const t = nodeMap.get(tId);
    if (!s || !t) continue;

    const strokeColor = link.type === 'traceroute' ? '#38bdf8' : '#64748b';
    const strokeWidth = coercePositiveSvgNumber(link.type === 'traceroute' ? 2 : 1.5, 1.5);
    const strokeDash = link.type === 'subnet' ? 'stroke-dasharray="4,4"' : '';

    const sx = coerceSvgNumber(s.x, 0);
    const sy = coerceSvgNumber(s.y, 0);
    const tx = coerceSvgNumber(t.x, 0);
    const ty = coerceSvgNumber(t.y, 0);
    const lineOpacity = coerceSvgNumber(0.6, 0.6);

    linksSvg += `
      <line x1="${escapeXml(sx)}" y1="${escapeXml(sy)}" x2="${escapeXml(tx)}" y2="${escapeXml(ty)}" stroke="${escapeXml(strokeColor)}" stroke-width="${escapeXml(strokeWidth)}" ${strokeDash} opacity="${escapeXml(lineOpacity)}" />
    `;

    if (link.label) {
      const midX = coerceSvgNumber((sx + tx) / 2, 0);
      const midY = coerceSvgNumber((sy + ty) / 2, 0);
      const labelY = coerceSvgNumber(midY - 4, -4);
      const linkFontSize = coercePositiveSvgNumber(10, 10);
      linksSvg += `
        <text x="${escapeXml(midX)}" y="${escapeXml(labelY)}" fill="#94a3b8" font-size="${escapeXml(linkFontSize)}" font-family="sans-serif" text-anchor="middle">${escapeXml(link.label)}</text>
      `;
    }
  }

  let nodesSvg = '';
  for (const node of nodes) {
    const isScanner = node.nodeType === 'scanner';
    const fill = sanitizeSvgColor(node.color, '#3b82f6');
    const stroke = escapeXml(isScanner ? '#a855f7' : node.status === 'up' ? '#22c55e' : '#ef4444');
    const nx = coerceSvgNumber(node.x, 0);
    const ny = coerceSvgNumber(node.y, 0);
    const r = coercePositiveSvgNumber(node.radius, 10);
    const nodeStrokeWidth = coercePositiveSvgNumber(2.5, 2.5);
    const labelY = coerceSvgNumber(r + 14, 24);
    const ipY = coerceSvgNumber(r + 26, 36);
    const labelFontSize = coercePositiveSvgNumber(11, 11);
    const ipFontSize = coercePositiveSvgNumber(9, 9);

    nodesSvg += `
      <g transform="translate(${escapeXml(nx)}, ${escapeXml(ny)})">
        <circle r="${escapeXml(r)}" fill="${fill}" stroke="${stroke}" stroke-width="${escapeXml(nodeStrokeWidth)}" />
        <text y="${escapeXml(labelY)}" fill="#f8fafc" font-size="${escapeXml(labelFontSize)}" font-family="sans-serif" font-weight="600" text-anchor="middle">${escapeXml(node.label)}</text>
        <text y="${escapeXml(ipY)}" fill="#94a3b8" font-size="${escapeXml(ipFontSize)}" font-family="monospace" text-anchor="middle">${escapeXml(node.ip)}</text>
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
  
  <text x="${escapeXml(titleX)}" y="${escapeXml(titleY)}" fill="#f8fafc" font-size="${escapeXml(titleFontSize)}" font-family="sans-serif" font-weight="bold">${escapeXml(title)}</text>
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
 * Generate a standalone HTML report with embedded styles and metadata.
 */
export function generateHtmlReport(scan: NmapRun, graph: TopologyGraph): string {
  const svgContent = generateHeadlessSvg(graph, {
    title: `Nmap Scan Report: ${scan.args || 'Network Scan'}`,
  });

  const hosts = Array.isArray(scan?.hosts) ? scan.hosts : [];
  const hostsList = hosts
    .map(
      (h) => {
        const statusState = h.status?.state || 'unknown';
        const ports = Array.isArray(h.ports) ? h.ports : [];
        return `
    <tr style="border-bottom: 1px solid #1e293b;">
      <td style="padding: 10px 14px; font-family: monospace; color: #38bdf8;">${escapeXml(h.ipv4 || h.id)}</td>
      <td style="padding: 10px 14px; color: #f8fafc;">${escapeXml(h.primaryHostname || '-')}</td>
      <td style="padding: 10px 14px;"><span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: ${statusState === 'up' ? '#065f46; color: #34d399;' : '#881337; color: #f87171;'}">${escapeXml(statusState.toUpperCase())}</span></td>
      <td style="padding: 10px 14px; color: #94a3b8;">${escapeXml(h.primaryOs || h.osFamily || 'Unknown')}</td>
      <td style="padding: 10px 14px; color: #cbd5e1;">${escapeXml(ports.filter((p) => p.state === 'open').map((p) => `${p.portid}/${p.protocol}`).join(', ') || 'None')}</td>
      <td style="padding: 10px 14px; color: #94a3b8;">${escapeXml(h.latencyMs !== undefined ? `${h.latencyMs} ms` : '-')}</td>
    </tr>
  `;
      }
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NastyMap - Nmap Security Scan Report</title>
  <style>
    body { margin: 0; padding: 24px; background-color: #0b0f19; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #1e293b; }
    .map-container { margin: 24px 0; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; background: #030712; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th { background: #111827; padding: 12px 14px; color: #94a3b8; font-weight: 600; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 style="margin: 0 0 8px 0; font-size: 24px; color: #38bdf8;">NastyMap Scan Report</h1>
      <p style="margin: 0; color: #94a3b8; font-family: monospace; font-size: 13px;">Command: ${escapeXml(scan.args)}</p>
      <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Scanned at ${escapeXml(scan.startstr)} · Nmap v${escapeXml(scan.version)} · ${escapeXml(coerceSvgNumber(hosts.length, 0))} Hosts</p>
    </div>

    <div class="map-container">
      ${svgContent}
    </div>

    <h2>Discovered Hosts & Services</h2>
    <div style="overflow-x: auto; border: 1px solid #1e293b; border-radius: 8px;">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>Status</th>
            <th>Operating System</th>
            <th>Open Ports</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          ${hostsList}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`;
}
