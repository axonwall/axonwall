import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { McpAuditLogEntry, McpAuditMetadata } from '@axonwall/lib/mcp';
import { acquireMcpLockFile } from './lockfile.js';
import { resolveControllerDirs } from '../dev-paths.js';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const MAX_PARAMS_SUMMARY_BYTES = 4096;
const MAX_DENIAL_REASON_CHARS = 2048;
const MAX_FIELD_CHARS = 256;
const DEFAULT_MAX_AUDIT_BYTES = 10 * 1024 * 1024;
const DEFAULT_MAX_AUDIT_ARCHIVES = 10;
const STREAM_CHUNK_BYTES = 64 * 1024;

interface AuditCheckpointMeta {
  version: number;
  anchorHash: string;
  checkpointEntryHash: string;
  rotatedTo: string;
  rotatedAt: string;
}

function resolveAuditMaxBytes(): number {
  const raw = process.env.AXONWALL_MCP_AUDIT_MAX_BYTES;
  if (raw) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 256) {
      return Math.floor(parsed);
    }
  }
  return DEFAULT_MAX_AUDIT_BYTES;
}

function resolveAuditMaxArchives(): number {
  const raw = process.env.AXONWALL_MCP_AUDIT_MAX_ARCHIVES;
  if (raw) {
    const parsed = Number(raw);
    if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 100) {
      return parsed;
    }
  }
  return DEFAULT_MAX_AUDIT_ARCHIVES;
}

function checkpointFilePath(auditPath: string): string {
  return `${auditPath}.checkpoint.json`;
}

function assertNotSymlink(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  const st = fs.lstatSync(filePath);
  if (st.isSymbolicLink()) {
    throw new Error(`Refusing symlinked MCP audit file: ${filePath}`);
  }
}

export function resolveMcpAuditPath(): string {
  const envOverride = process.env.AXONWALL_MCP_AUDIT_PATH?.trim();
  if (envOverride) {
    return envOverride;
  }
  const dirs = resolveControllerDirs();
  for (const dir of Array.from(new Set([dirs.varDir, dirs.logDir]))) {
    const file = path.join(dir, 'mcp-audit.jsonl');
    try {
      if (fs.existsSync(file)) {
        assertNotSymlink(file);
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
  // Never fall back to predictable /tmp/axonwall paths: use a 0700 directory
  // under /run/axonwall (or devRoot/run in devMode), or fail closed.
  const runAuditDir = path.join(dirs.runDir, 'mcp-audit');
  try {
    fs.mkdirSync(runAuditDir, { recursive: true, mode: 0o700 });
    const st = fs.lstatSync(runAuditDir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new Error(`Invalid audit directory ${runAuditDir}`);
    }
    if (typeof process.getuid === 'function' && st.uid === process.getuid() && (st.mode & 0o077) !== 0) {
      fs.chmodSync(runAuditDir, 0o700);
    }
    fs.accessSync(runAuditDir, fs.constants.W_OK);
    const file = path.join(runAuditDir, 'mcp-audit.jsonl');
    assertNotSymlink(file);
    return file;
  } catch (err: any) {
    throw new Error(
      `No writable secure MCP audit directory available (checked varDir, logDir, and 0700 ${runAuditDir}; refusing /tmp fallback): ${err?.message || err}`
    );
  }
}

function truncateStringToJsonBytes(str: string, maxJsonBytes: number): string {
  if (maxJsonBytes <= 2) return '';
  let lo = 0;
  let hi = str.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const candidate = str.slice(0, mid);
    if (Buffer.byteLength(JSON.stringify(candidate), 'utf8') <= maxJsonBytes) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  if (lo > 0 && lo < str.length) {
    const code = str.charCodeAt(lo - 1);
    if (code >= 0xd800 && code <= 0xdbff) {
      lo -= 1;
    }
  }
  return str.slice(0, lo);
}

function sanitizeAndCapParamsSummary(raw: unknown): Record<string, unknown> {
  const input = raw === undefined ? {} : raw;
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(input);
  } catch {
    serialized = undefined;
  }
  if (serialized !== undefined && Buffer.byteLength(serialized, 'utf8') <= MAX_PARAMS_SUMMARY_BYTES) {
    return input as Record<string, unknown>;
  }
  const originalBytes = serialized ? Buffer.byteLength(serialized, 'utf8') : -1;
  const out: Record<string, unknown> = {
    _truncated: true,
    _originalBytes: originalBytes,
  };
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (k === '_truncated' || k === '_originalBytes') continue;
      const safeKey = k.length > 64 ? k.slice(0, 64) : k;
      let valJson: string;
      try {
        valJson = JSON.stringify(v) ?? String(v);
      } catch {
        valJson = '[unserializable]';
      }
      const candidateWhole = { ...out, [safeKey]: v };
      try {
        if (Buffer.byteLength(JSON.stringify(candidateWhole), 'utf8') <= MAX_PARAMS_SUMMARY_BYTES) {
          out[safeKey] = v;
          continue;
        }
      } catch {
        // fall through to string preview
      }
      const currentBytes = Buffer.byteLength(JSON.stringify(out), 'utf8');
      const keyOverhead = Buffer.byteLength(JSON.stringify(safeKey), 'utf8') + 6;
      const suffix = '...[truncated]';
      const budget = MAX_PARAMS_SUMMARY_BYTES - currentBytes - keyOverhead - suffix.length;
      if (budget > 16) {
        const preview = `${truncateStringToJsonBytes(valJson, budget)}${suffix}`;
        const candidatePreview = { ...out, [safeKey]: preview };
        if (Buffer.byteLength(JSON.stringify(candidatePreview), 'utf8') <= MAX_PARAMS_SUMMARY_BYTES) {
          out[safeKey] = preview;
        }
      }
      if (Buffer.byteLength(JSON.stringify(out), 'utf8') >= MAX_PARAMS_SUMMARY_BYTES - 48) {
        break;
      }
    }
  } else if (serialized) {
    const baseBytes = Buffer.byteLength(JSON.stringify(out), 'utf8');
    const suffix = '...[truncated]';
    const budget = MAX_PARAMS_SUMMARY_BYTES - baseBytes - 24 - suffix.length;
    if (budget > 16) {
      const preview = `${truncateStringToJsonBytes(serialized, budget)}${suffix}`;
      const candidate = { ...out, preview };
      if (Buffer.byteLength(JSON.stringify(candidate), 'utf8') <= MAX_PARAMS_SUMMARY_BYTES) {
        out.preview = preview;
      }
    }
  }
  return out;
}

function capField(val: string, maxLen: number): string {
  if (val.length <= maxLen) return val;
  return `${val.slice(0, Math.max(0, maxLen - 14))}...[truncated]`;
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

function isWhitespaceByte(b: number): boolean {
  return b === 0x0a || b === 0x0d || b === 0x20 || b === 0x09;
}

function getLastHash(auditPath: string): string {
  if (!fs.existsSync(auditPath)) {
    if (fs.existsSync(checkpointFilePath(auditPath))) {
      throw new Error(`Audit log ${auditPath} is missing while rotation checkpoint exists`);
    }
    return GENESIS_HASH;
  }
  assertNotSymlink(auditPath);
  const fd = fs.openSync(auditPath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (stat.size <= 0) {
      if (fs.existsSync(checkpointFilePath(auditPath))) {
        throw new Error(`Audit log ${auditPath} is empty while rotation checkpoint exists`);
      }
      return GENESIS_HASH;
    }

    // 1. Scan backwards in chunks to skip trailing whitespace/newlines at EOF.
    const chunkBuf = Buffer.allocUnsafe(STREAM_CHUNK_BYTES);
    let endPos = stat.size;
    while (endPos > 0) {
      const readSize = Math.min(STREAM_CHUNK_BYTES, endPos);
      const startOffset = endPos - readSize;
      const bytesRead = fs.readSync(fd, chunkBuf, 0, readSize, startOffset);
      let idx = bytesRead - 1;
      while (idx >= 0 && isWhitespaceByte(chunkBuf[idx]!)) {
        idx--;
      }
      if (idx >= 0) {
        endPos = startOffset + idx + 1;
        break;
      }
      endPos = startOffset;
    }

    if (endPos === 0) {
      throw new Error(`Non-empty audit log ${auditPath} contains only whitespace with no valid entryHash`);
    }

    // 2. Scan backwards in chunks from endPos until the preceding '\n' or byte 0.
    const lineChunks: Buffer[] = [];
    let scanPos = endPos;
    while (scanPos > 0) {
      const readSize = Math.min(STREAM_CHUNK_BYTES, scanPos);
      const startOffset = scanPos - readSize;
      const chunk = Buffer.allocUnsafe(readSize);
      const bytesRead = fs.readSync(fd, chunk, 0, readSize, startOffset);
      const slice = chunk.subarray(0, bytesRead);
      const nlIdx = slice.lastIndexOf(0x0a);
      if (nlIdx >= 0) {
        lineChunks.unshift(slice.subarray(nlIdx + 1));
        break;
      }
      lineChunks.unshift(slice);
      scanPos = startOffset;
    }

    const lastLine = Buffer.concat(lineChunks).toString('utf8').trim();
    if (!lastLine) {
      throw new Error(`Failed to extract final entry from non-empty audit log ${auditPath}`);
    }
    const parsed = JSON.parse(lastLine) as McpAuditLogEntry;
    if (!parsed || typeof parsed.entryHash !== 'string' || !/^[a-f0-9]{64}$/.test(parsed.entryHash)) {
      throw new Error(`Final entry in ${auditPath} lacks a valid 64-hex entryHash`);
    }
    return parsed.entryHash;
  } finally {
    fs.closeSync(fd);
  }
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

function buildAuditEntry(input: RecordAuditInput, prevHash: string): McpAuditLogEntry {
  const partial: Omit<McpAuditLogEntry, 'entryHash'> = {
    id: `mcp_aud_${crypto.randomBytes(6).toString('hex')}`,
    timestamp: new Date().toISOString(),
    keyId: capField(String(input.keyId || ''), MAX_FIELD_CHARS),
    keyName: capField(String(input.keyName || ''), MAX_FIELD_CHARS),
    agentType: capField(String(input.agentType || ''), MAX_FIELD_CHARS),
    clientIp: capField(String(input.clientIp || ''), MAX_FIELD_CHARS),
    toolName: capField(String(input.toolName || ''), MAX_FIELD_CHARS),
    requiredScope: capField(String(input.requiredScope || ''), MAX_FIELD_CHARS),
    decision: input.decision,
    denialReason:
      input.denialReason !== undefined ? capField(String(input.denialReason), MAX_DENIAL_REASON_CHARS) : undefined,
    paramsSummary: sanitizeAndCapParamsSummary(input.paramsSummary),
    auditMetadata: input.auditMetadata,
    leaseId: input.leaseId !== undefined ? capField(String(input.leaseId), MAX_FIELD_CHARS) : undefined,
    prevHash,
  };

  const entryHash = computeEntryHash(partial);
  return {
    ...partial,
    entryHash,
  };
}

function writeFileAtomicSync(filePath: string, data: string, mode = 0o660): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o775 });
  const tmpPath = `${filePath}.tmp.${process.pid}.${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(tmpPath, data, { mode });
    try {
      fs.chmodSync(tmpPath, mode);
    } catch {}
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {}
    throw err;
  }
}

function isCheckpointEntry(entry: McpAuditLogEntry): boolean {
  return (
    entry.toolName === 'audit:checkpoint' &&
    typeof entry.paramsSummary === 'object' &&
    entry.paramsSummary !== null &&
    (entry.paramsSummary as Record<string, unknown>)._checkpoint === true
  );
}

function rotateAuditLogIfNeeded(auditPath: string, maxBytes: number): string | null {
  if (!fs.existsSync(auditPath)) return null;
  assertNotSymlink(auditPath);
  const stat = fs.statSync(auditPath);
  if (stat.size < maxBytes) return null;

  const prevHeadHash = getLastHash(auditPath);
  const maxArchives = resolveAuditMaxArchives();
  for (let i = maxArchives; i >= 2; i--) {
    const src = `${auditPath}.${i - 1}`;
    const dst = `${auditPath}.${i}`;
    if (fs.existsSync(src)) {
      assertNotSymlink(src);
      fs.renameSync(src, dst);
    }
  }
  const firstArchive = `${auditPath}.1`;
  fs.renameSync(auditPath, firstArchive);
  try {
    fs.chmodSync(firstArchive, 0o660);
  } catch {}

  const rotatedAt = new Date().toISOString();
  const checkpointEntry = buildAuditEntry(
    {
      keyId: 'system',
      keyName: 'audit-rotation',
      agentType: 'system',
      clientIp: '127.0.0.1',
      toolName: 'audit:checkpoint',
      requiredScope: 'mcp:audit',
      decision: 'allowed',
      paramsSummary: {
        _checkpoint: true,
        anchorPrevHash: prevHeadHash,
        rotatedTo: path.basename(firstArchive),
        rotatedAt,
      },
    },
    prevHeadHash
  );

  writeFileAtomicSync(auditPath, JSON.stringify(checkpointEntry) + '\n', 0o660);
  const meta: AuditCheckpointMeta = {
    version: 1,
    anchorHash: prevHeadHash,
    checkpointEntryHash: checkpointEntry.entryHash,
    rotatedTo: path.basename(firstArchive),
    rotatedAt,
  };
  writeFileAtomicSync(checkpointFilePath(auditPath), JSON.stringify(meta, null, 2), 0o660);
  return checkpointEntry.entryHash;
}

export type RecordedMcpAuditEntry = McpAuditLogEntry & { recorded: boolean };

export function recordMcpAuditEntry(input: RecordAuditInput): RecordedMcpAuditEntry {
  let auditPath: string;
  try {
    auditPath = resolveMcpAuditPath();
  } catch (err) {
    console.error('[MCP Audit] Failed to resolve secure audit path; entry not recorded:', err);
    return { ...buildAuditEntry(input, GENESIS_HASH), recorded: false };
  }

  // B-S2: appending is read-last-hash + append, and at least two
  // processes write this log (HTTP controller and stdio MCP server).
  // Without serialisation, two writers that read the same tail hash
  // both append entries chaining to it, forking the chain and
  // failing every later verification. Hold an exclusive lockfile
  // across the read-tail + append so the chain stays linear.
  let release: (() => void) | null = null;
  try {
    release = acquireMcpLockFile(`${auditPath}.lock`);
  } catch (err: any) {
    // A lock that cannot be acquired must not fork the chain: skip
    // the append (the entry is returned unrecorded) rather than
    // writing an entry chained to a stale tail hash.
    // B2-L6: mark the entry unrecorded. Callers used to embed
    // entryHash in success responses unconditionally, handing out a
    // hash that does not exist in the log.
    console.error('[MCP Audit] Failed to acquire audit lock; entry not recorded:', err);
    let tailHash = GENESIS_HASH;
    try {
      tailHash = getLastHash(auditPath);
    } catch {
      tailHash = GENESIS_HASH;
    }
    return { ...buildAuditEntry(input, tailHash), recorded: false };
  }

  try {
    let prevHash: string;
    try {
      const rotatedHead = rotateAuditLogIfNeeded(auditPath, resolveAuditMaxBytes());
      prevHash = rotatedHead ?? getLastHash(auditPath);
    } catch (err) {
      console.error('[MCP Audit] Cannot read tail hash / rotate non-empty audit log; entry not recorded:', err);
      return { ...buildAuditEntry(input, GENESIS_HASH), recorded: false };
    }
    const fullEntry = buildAuditEntry(input, prevHash);
    try {
      fs.mkdirSync(path.dirname(auditPath), { recursive: true, mode: 0o775 });
      assertNotSymlink(auditPath);
      fs.appendFileSync(auditPath, JSON.stringify(fullEntry) + '\n', { mode: 0o660 });
      try {
        fs.chmodSync(auditPath, 0o660);
      } catch {}
    } catch (err) {
      // B2-L6: an append failure (disk full, perms) used to return
      // the entry as if recorded, with a verifiable-looking hash.
      console.error('[MCP Audit] Failed to append audit entry:', err);
      return { ...fullEntry, recorded: false };
    }
    return { ...fullEntry, recorded: true };
  } finally {
    release();
  }
}

export interface AuditChainVerification {
  valid: boolean;
  totalEntries: number;
  brokenAtIndex?: number;
  brokenEntryId?: string;
  headHash: string;
}

function forEachLineSync(filePath: string, onLine: (line: string) => void): void {
  assertNotSymlink(filePath);
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.allocUnsafe(STREAM_CHUNK_BYTES);
  let leftover: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  try {
    for (;;) {
      const bytesRead = fs.readSync(fd, buf, 0, STREAM_CHUNK_BYTES, null);
      if (bytesRead === 0) break;
      const slice = buf.subarray(0, bytesRead);
      let start = 0;
      let nlIdx = slice.indexOf(0x0a, start);
      while (nlIdx !== -1) {
        const part = slice.subarray(start, nlIdx);
        const lineBuf = leftover.length > 0 ? Buffer.concat([leftover, part]) : part;
        leftover = Buffer.alloc(0);
        const lineStr = lineBuf.toString('utf8').trim();
        if (lineStr.length > 0) {
          onLine(lineStr);
        }
        start = nlIdx + 1;
        nlIdx = slice.indexOf(0x0a, start);
      }
      if (start < slice.length) {
        const rem = slice.subarray(start);
        leftover = leftover.length > 0 ? Buffer.concat([leftover, rem]) : Buffer.from(rem);
      }
    }
    if (leftover.length > 0) {
      const lineStr = leftover.toString('utf8').trim();
      if (lineStr.length > 0) {
        onLine(lineStr);
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}

function readCheckpointMetaSafe(auditPath: string): { present: boolean; meta: AuditCheckpointMeta | null } {
  const cpPath = checkpointFilePath(auditPath);
  if (!fs.existsSync(cpPath)) return { present: false, meta: null };
  try {
    assertNotSymlink(cpPath);
    const stat = fs.lstatSync(cpPath);
    if (!stat.isFile() || stat.size > 65536) return { present: true, meta: null };
    const parsed = JSON.parse(fs.readFileSync(cpPath, 'utf8')) as Partial<AuditCheckpointMeta>;
    if (
      parsed &&
      parsed.version === 1 &&
      typeof parsed.anchorHash === 'string' &&
      /^[a-f0-9]{64}$/.test(parsed.anchorHash) &&
      typeof parsed.checkpointEntryHash === 'string' &&
      /^[a-f0-9]{64}$/.test(parsed.checkpointEntryHash)
    ) {
      return { present: true, meta: parsed as AuditCheckpointMeta };
    }
  } catch {
    // malformed checkpoint
  }
  return { present: true, meta: null };
}

function verifyAndCollectAuditEntries(collectLimit: number): {
  entries: McpAuditLogEntry[];
  integrity: AuditChainVerification;
} {
  let auditPath: string;
  try {
    auditPath = resolveMcpAuditPath();
  } catch {
    return {
      entries: [],
      integrity: { valid: false, totalEntries: 0, headHash: '' },
    };
  }

  const maxArchives = resolveAuditMaxArchives();
  let highestArchive = 0;
  for (let i = maxArchives; i >= 1; i--) {
    if (fs.existsSync(`${auditPath}.${i}`)) {
      highestArchive = i;
      break;
    }
  }
  const archiveFiles: string[] = [];
  let missingArchiveGap = false;
  for (let i = highestArchive; i >= 1; i--) {
    const candidate = `${auditPath}.${i}`;
    if (!fs.existsSync(candidate)) {
      missingArchiveGap = true;
    } else {
      archiveFiles.push(candidate);
    }
  }

  const cpState = readCheckpointMetaSafe(auditPath);
  const activeExists = fs.existsSync(auditPath);
  if (!activeExists && archiveFiles.length === 0 && !cpState.present) {
    return {
      entries: [],
      integrity: { valid: true, totalEntries: 0, headHash: GENESIS_HASH },
    };
  }

  if (!activeExists || missingArchiveGap || (cpState.present && !cpState.meta)) {
    return {
      entries: [],
      integrity: { valid: false, totalEntries: 0, brokenAtIndex: 0, headHash: '' },
    };
  }

  const filesToStream = [...archiveFiles, auditPath];
  let totalEntries = 0;
  let expectedPrev = GENESIS_HASH;
  let firstBreak: { index: number; id?: string; headHash: string } | null = null;
  let activeFileFirstEntryVerified = false;
  let activeFileHasLines = false;
  const ring: McpAuditLogEntry[] = [];

  for (let fIdx = 0; fIdx < filesToStream.length; fIdx++) {
    const file = filesToStream[fIdx]!;
    const isActiveFile = fIdx === filesToStream.length - 1;
    let firstInFile = true;

    try {
      forEachLineSync(file, (line) => {
        const currentIndex = totalEntries;
        totalEntries++;
        if (isActiveFile) activeFileHasLines = true;

        let entry: McpAuditLogEntry;
        try {
          entry = JSON.parse(line) as McpAuditLogEntry;
        } catch {
          if (!firstBreak) {
            firstBreak = { index: currentIndex, headHash: expectedPrev };
          }
          firstInFile = false;
          return;
        }

        const checkpoint = isCheckpointEntry(entry);
        if (collectLimit > 0 && !checkpoint) {
          ring.push(entry);
          if (ring.length > collectLimit) ring.shift();
        }

        if (!firstBreak) {
          if (fIdx === 0 && firstInFile && checkpoint) {
            const anchorPrev = (entry.paramsSummary as Record<string, unknown>).anchorPrevHash;
            const anchorValid = typeof anchorPrev === 'string' && /^[a-f0-9]{64}$/.test(anchorPrev);
            // If no rotated archives exist on disk, an active file starting at a checkpoint
            // must be corroborated by the checkpoint metadata file to prevent genesis spoofing.
            const metaValid =
              archiveFiles.length > 0 ||
              (cpState.meta !== null &&
                cpState.meta.anchorHash === entry.prevHash &&
                cpState.meta.checkpointEntryHash === entry.entryHash);
            if (!anchorValid || !metaValid || entry.prevHash !== anchorPrev) {
              firstBreak = { index: currentIndex, id: entry.id, headHash: entry.entryHash || '' };
              firstInFile = false;
              return;
            }
            expectedPrev = entry.prevHash;
          } else if (fIdx > 0 && firstInFile) {
            if (!checkpoint) {
              firstBreak = { index: currentIndex, id: entry.id, headHash: entry.entryHash || '' };
              firstInFile = false;
              return;
            }
            const anchorPrev = (entry.paramsSummary as Record<string, unknown>).anchorPrevHash;
            if (anchorPrev !== expectedPrev) {
              firstBreak = { index: currentIndex, id: entry.id, headHash: entry.entryHash || '' };
              firstInFile = false;
              return;
            }
          }

          if (isActiveFile && firstInFile) {
            activeFileFirstEntryVerified = true;
            if (cpState.meta) {
              if (
                !checkpoint ||
                entry.prevHash !== cpState.meta.anchorHash ||
                entry.entryHash !== cpState.meta.checkpointEntryHash
              ) {
                firstBreak = { index: currentIndex, id: entry.id, headHash: entry.entryHash || '' };
                firstInFile = false;
                return;
              }
            }
          }

          if (entry.prevHash !== expectedPrev) {
            firstBreak = { index: currentIndex, id: entry.id, headHash: entry.entryHash || '' };
            firstInFile = false;
            return;
          }

          const recomputed = computeEntryHash(entry);
          if (recomputed !== entry.entryHash) {
            firstBreak = { index: currentIndex, id: entry.id, headHash: entry.entryHash || '' };
            firstInFile = false;
            return;
          }

          expectedPrev = entry.entryHash;
        }
        firstInFile = false;
      });
    } catch {
      if (!firstBreak) {
        firstBreak = { index: totalEntries, headHash: expectedPrev };
      }
    }
  }

  if (totalEntries === 0 && (archiveFiles.length > 0 || cpState.present)) {
    return {
      entries: [],
      integrity: { valid: false, totalEntries: 0, brokenAtIndex: 0, headHash: '' },
    };
  }

  if (!activeFileHasLines && (archiveFiles.length > 0 || cpState.present)) {
    return {
      entries: ring.reverse(),
      integrity: { valid: false, totalEntries, brokenAtIndex: totalEntries, headHash: expectedPrev },
    };
  }

  if (cpState.present && !activeFileFirstEntryVerified && !firstBreak) {
    firstBreak = { index: totalEntries, headHash: expectedPrev };
  }

  if (firstBreak) {
    return {
      entries: ring.reverse(),
      integrity: {
        valid: false,
        totalEntries,
        brokenAtIndex: firstBreak.index,
        ...(firstBreak.id ? { brokenEntryId: firstBreak.id } : {}),
        headHash: firstBreak.headHash,
      },
    };
  }

  return {
    entries: ring.reverse(),
    integrity: {
      valid: true,
      totalEntries,
      headHash: expectedPrev,
    },
  };
}

export function verifyMcpAuditChain(): AuditChainVerification {
  return verifyAndCollectAuditEntries(0).integrity;
}

export function queryMcpAuditEntries(limit = 100): {
  entries: McpAuditLogEntry[];
  integrity: AuditChainVerification;
} {
  const safeLimit = Number.isFinite(limit) ? Math.max(0, Math.floor(limit)) : 100;
  return verifyAndCollectAuditEntries(safeLimit);
}
