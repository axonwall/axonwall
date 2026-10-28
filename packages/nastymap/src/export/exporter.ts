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
  const scale = options.scale || 2;
  const bgColor = options.backgroundColor || '#090d16';

  if (sourceElement instanceof HTMLCanvasElement) {
    sourceElement.toBlob((blob) => {
      if (blob) downloadBlob(blob, filename);
    }, 'image/png', options.quality || 0.95);
    return;
  }

  // If SVG element, render onto a canvas
  const bbox = sourceElement.getBoundingClientRect();
  const width = (bbox.width || 1200) * scale;
  const height = (bbox.height || 800) * scale;

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // Background
  ctx.fillStyle = bgColor;
  ctx.fillRect(0, 0, width, height);

  const serializer = new XMLSerializer();
  const svgString = serializer.serializeToString(sourceElement);
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
      }, 'image/png', options.quality || 0.95);
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

/**
 * Programmatic headless generator: creates an SVG string representation of a TopologyGraph
 * without requiring a DOM (can run in Node.js / CLI / CI report generator).
 */
export function generateHeadlessSvg(
  graph: TopologyGraph,
  options: { width?: number; height?: number; title?: string } = {}
): string {
  const width = options.width || 1200;
  const height = options.height || 800;
  const title = options.title || 'Nmap Network Topology Map';

  const nodeMap = new Map<string, typeof graph.nodes[0]>();
  for (const n of graph.nodes) nodeMap.set(n.id, n);

  let linksSvg = '';
  for (const link of graph.links) {
    const sId = typeof link.source === 'string' ? link.source : (link.source as any).id;
    const tId = typeof link.target === 'string' ? link.target : (link.target as any).id;
    const s = nodeMap.get(sId);
    const t = nodeMap.get(tId);
    if (!s || !t) continue;

    const strokeColor = link.type === 'traceroute' ? '#38bdf8' : '#64748b';
    const strokeWidth = link.type === 'traceroute' ? 2 : 1.5;
    const strokeDash = link.type === 'subnet' ? 'stroke-dasharray="4,4"' : '';

    const sx = Number(s.x) || 0;
    const sy = Number(s.y) || 0;
    const tx = Number(t.x) || 0;
    const ty = Number(t.y) || 0;

    linksSvg += `
      <line x1="${sx}" y1="${sy}" x2="${tx}" y2="${ty}" stroke="${strokeColor}" stroke-width="${strokeWidth}" ${strokeDash} opacity="0.6" />
    `;

    if (link.label) {
      const midX = (sx + tx) / 2;
      const midY = (sy + ty) / 2;
      linksSvg += `
        <text x="${midX}" y="${midY - 4}" fill="#94a3b8" font-size="10" font-family="sans-serif" text-anchor="middle">${escapeXml(link.label)}</text>
      `;
    }
  }

  let nodesSvg = '';
  for (const node of graph.nodes) {
    const isScanner = node.nodeType === 'scanner';
    const fill = escapeXml(node.color || '#3b82f6');
    const stroke = isScanner ? '#a855f7' : node.status === 'up' ? '#22c55e' : '#ef4444';
    const nx = Number(node.x) || 0;
    const ny = Number(node.y) || 0;
    const r = Number(node.radius) || 10;

    nodesSvg += `
      <g transform="translate(${nx}, ${ny})">
        <circle r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="2.5" />
        <text y="${r + 14}" fill="#f8fafc" font-size="11" font-family="sans-serif" font-weight="600" text-anchor="middle">${escapeXml(node.label)}</text>
        <text y="${r + 26}" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">${escapeXml(node.ip)}</text>
      </g>
    `;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" style="background-color: #0b0f19;">
  <defs>
    <radialGradient id="bgGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#1e1b4b" stop-opacity="0.5" />
      <stop offset="100%" stop-color="#0b0f19" stop-opacity="0" />
    </radialGradient>
  </defs>
  <rect width="100%" height="100%" fill="#0b0f19" />
  <circle cx="${width / 2}" cy="${height / 2}" r="${Math.min(width, height) * 0.45}" fill="url(#bgGlow)" />
  
  <text x="24" y="36" fill="#f8fafc" font-size="18" font-family="sans-serif" font-weight="bold">${escapeXml(title)}</text>
  <text x="24" y="56" fill="#64748b" font-size="12" font-family="monospace">Generated with NastyMap · ${graph.nodes.length} nodes · ${graph.links.length} links</text>

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

  const hostsList = scan.hosts
    .map(
      (h) => `
    <tr style="border-bottom: 1px solid #1e293b;">
      <td style="padding: 10px 14px; font-family: monospace; color: #38bdf8;">${escapeXml(h.ipv4 || h.id)}</td>
      <td style="padding: 10px 14px; color: #f8fafc;">${escapeXml(h.primaryHostname || '-')}</td>
      <td style="padding: 10px 14px;"><span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: ${h.status.state === 'up' ? '#065f46; color: #34d399;' : '#881337; color: #f87171;'}">${escapeXml(h.status.state.toUpperCase())}</span></td>
      <td style="padding: 10px 14px; color: #94a3b8;">${escapeXml(h.primaryOs || h.osFamily || 'Unknown')}</td>
      <td style="padding: 10px 14px; color: #cbd5e1;">${escapeXml(h.ports.filter((p) => p.state === 'open').map((p) => `${p.portid}/${p.protocol}`).join(', ') || 'None')}</td>
      <td style="padding: 10px 14px; color: #94a3b8;">${escapeXml(h.latencyMs !== undefined ? `${h.latencyMs} ms` : '-')}</td>
    </tr>
  `
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
      <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Scanned at ${escapeXml(scan.startstr)} · Nmap v${escapeXml(scan.version)} · ${scan.hosts.length} Hosts</p>
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
