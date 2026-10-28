import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { McpAuditLogEntry, McpAuditMetadata } from '@axonwall/lib/mcp';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export function resolveMcpAuditPath(): string {
  if (process.env.AXONWALL_MCP_AUDIT_PATH) {
    return process.env.AXONWALL_MCP_AUDIT_PATH;
  }
  for (const dir of ['/var/lib/axonwall', '/var/log/axonwall']) {
    const file = path.join(dir, 'mcp-audit.jsonl');
    try {
      if (fs.existsSync(file)) {
        fs.accessSync(file, fs.constants.W_OK);
        return file;
      }
      fs.mkdirSync(dir, { recursive: true, mode: 0o775 });
      fs.accessSync(dir, fs.constants.W_OK);
      return file;
    } catch {
      // try next candidate
    }
  }
  const fallbackDir = '/tmp/axonwall';
  fs.mkdirSync(fallbackDir, { recursive: true, mode: 0o775 });
  return path.join(fallbackDir, 'mcp-audit.jsonl');
}

function computeEntryHash(entryWithoutHash: Omit<McpAuditLogEntry, 'entryHash'>): string {
  const canonical = JSON.stringify({
    id: entryWithoutHash.id,
    timestamp: entryWithoutHash.timestamp,
    keyId: entryWithoutHash.keyId,
    keyName: entryWithoutHash.keyName,
    agentType: entryWithoutHash.agentType,
    clientIp: entryWithoutHash.clientIp,
    toolName: entryWithoutHash.toolName,
    requiredScope: entryWithoutHash.requiredScope,
    decision: entryWithoutHash.decision,
    denialReason: entryWithoutHash.denialReason ?? null,
    paramsSummary: entryWithoutHash.paramsSummary,
    auditMetadata: entryWithoutHash.auditMetadata ?? null,
    leaseId: entryWithoutHash.leaseId ?? null,
    prevHash: entryWithoutHash.prevHash,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function getLastHash(auditPath: string): string {
  try {
    if (!fs.existsSync(auditPath)) return GENESIS_HASH;
    const content = fs.readFileSync(auditPath, 'utf8').trim();
    if (!content) return GENESIS_HASH;
    const lines = content.split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i]?.trim();
      if (!line) continue;
      const parsed = JSON.parse(line) as McpAuditLogEntry;
      if (parsed.entryHash) return parsed.entryHash;
    }
  } catch {
    // Fall back to genesis if unreadable
  }
  return GENESIS_HASH;
}

export interface RecordAuditInput {
  keyId: string;
  keyName: string;
  agentType: string;
  clientIp: string;
  toolName: string;
  requiredScope: string;
  decision: 'allowed' | 'denied' | 'failed';
  denialReason?: string;
  paramsSummary: Record<string, unknown>;
  auditMetadata?: McpAuditMetadata;
  leaseId?: string;
}

export function recordMcpAuditEntry(input: RecordAuditInput): McpAuditLogEntry {
  const auditPath = resolveMcpAuditPath();
  const prevHash = getLastHash(auditPath);

  const partial: Omit<McpAuditLogEntry, 'entryHash'> = {
    id: `mcp_aud_${crypto.randomBytes(6).toString('hex')}`,
    timestamp: new Date().toISOString(),
    keyId: input.keyId,
    keyName: input.keyName,
    agentType: input.agentType,
    clientIp: input.clientIp,
    toolName: input.toolName,
    requiredScope: input.requiredScope,
    decision: input.decision,
    denialReason: input.denialReason,
    paramsSummary: input.paramsSummary,
    auditMetadata: input.auditMetadata,
    leaseId: input.leaseId,
    prevHash,
  };

  const entryHash = computeEntryHash(partial);
  const fullEntry: McpAuditLogEntry = {
    ...partial,
    entryHash,
  };

  try {
    fs.mkdirSync(path.dirname(auditPath), { recursive: true, mode: 0o775 });
    fs.appendFileSync(auditPath, JSON.stringify(fullEntry) + '\n', { mode: 0o660 });
    try {
      fs.chmodSync(auditPath, 0o660);
    } catch {}
  } catch (err) {
    console.error('[MCP Audit] Failed to append audit entry:', err);
  }

  return fullEntry;
}

export interface AuditChainVerification {
  valid: boolean;
  totalEntries: number;
  brokenAtIndex?: number;
  brokenEntryId?: string;
  headHash: string;
}

export function verifyMcpAuditChain(): AuditChainVerification {
  const auditPath = resolveMcpAuditPath();
  if (!fs.existsSync(auditPath)) {
    return { valid: true, totalEntries: 0, headHash: GENESIS_HASH };
  }

  const raw = fs.readFileSync(auditPath, 'utf8').trim();
  if (!raw) {
    return { valid: true, totalEntries: 0, headHash: GENESIS_HASH };
  }

  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  let expectedPrev = GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    try {
      const entry = JSON.parse(lines[i]!) as McpAuditLogEntry;
      if (entry.prevHash !== expectedPrev) {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAtIndex: i,
          brokenEntryId: entry.id,
          headHash: entry.entryHash || '',
        };
      }
      const recomputed = computeEntryHash(entry);
      if (recomputed !== entry.entryHash) {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAtIndex: i,
          brokenEntryId: entry.id,
          headHash: entry.entryHash || '',
        };
      }
      expectedPrev = entry.entryHash;
    } catch {
      return {
        valid: false,
        totalEntries: lines.length,
        brokenAtIndex: i,
        headHash: expectedPrev,
      };
    }
  }

  return {
    valid: true,
    totalEntries: lines.length,
    headHash: expectedPrev,
  };
}

export function queryMcpAuditEntries(limit = 100): {
  entries: McpAuditLogEntry[];
  integrity: AuditChainVerification;
} {
  const auditPath = resolveMcpAuditPath();
  const integrity = verifyMcpAuditChain();
  if (!fs.existsSync(auditPath)) {
    return { entries: [], integrity };
  }

  const raw = fs.readFileSync(auditPath, 'utf8').trim();
  if (!raw) {
    return { entries: [], integrity };
  }

  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  const slice = lines.slice(Math.max(0, lines.length - limit)).reverse();
  const entries: McpAuditLogEntry[] = [];
  for (const line of slice) {
    try {
      entries.push(JSON.parse(line) as McpAuditLogEntry);
    } catch {
      // Skip malformed line
    }
  }

  return { entries, integrity };
}
