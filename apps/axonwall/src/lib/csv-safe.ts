/**
 * Safe CSV cell escaping and formula-injection neutralization (SEC-M19).
 * Matches packages/axonwall_lib/src/compile/topology/index.ts while also
 * neutralizing formula triggers preceded by leading whitespace.
 */

const FORMULA_TRIGGER_RE = /^\s*[=+\-@\t\r]/;

/**
 * Neutralizes spreadsheet formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`,
 * including after leading whitespace) with a leading `'` and collapses `\r\n`
 * to a single space.
 */
export function sanitizeCsvCellValue(value: unknown): string {
  let clean = String(value ?? '').replace(/[\r\n]+/g, ' ');
  if (FORMULA_TRIGGER_RE.test(clean)) {
    clean = `'${clean}`;
  }
  return clean;
}

/**
 * Formats a CSV cell, quoting only when needed (matching topology/index.ts).
 */
export function escapeCsvCell(value: unknown): string {
  const clean = sanitizeCsvCellValue(value);
  if (clean.includes(',') || clean.includes('"')) {
    return `"${clean.replace(/"/g, '""')}"`;
  }
  return clean;
}

/**
 * Formats a CSV cell always enclosed in double quotes with internal quotes doubled.
 */
export function formatCsvQuotedCell(value: unknown): string {
  const clean = sanitizeCsvCellValue(value);
  return `"${clean.replace(/"/g, '""')}"`;
}

export interface FlowPacketCsvRow {
  index: number | string;
  timestamp: string;
  protocol: string;
  srcIp: string;
  srcPort: number | string;
  dstIp: string;
  dstPort: number | string;
  length: number | string;
  info: string;
}

export function buildPacketTraceCsv(packets: readonly FlowPacketCsvRow[]): string {
  const header =
    'Index,Timestamp,Protocol,SourceIP,SourcePort,DestinationIP,DestinationPort,Length,Info\n';
  const rows = packets
    .map((p) =>
      [
        p.index,
        p.timestamp,
        p.protocol,
        p.srcIp,
        p.srcPort,
        p.dstIp,
        p.dstPort,
        p.length,
        p.info,
      ]
        .map(formatCsvQuotedCell)
        .join(',')
    )
    .join('\n');
  return header + rows;
}
