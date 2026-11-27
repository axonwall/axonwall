/**
 * VIGILANTE Cryptographic Merkle Ledger & Legal Chain-of-Custody Engine
 * Provides immutable append-only hash chaining, Merkle tree root calculation,
 * cryptographic inclusion proofs, tamper detection, and legal evidence verification.
 */

import fs from 'node:fs/promises';
import fsSync, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';
import { requireLedgerSigningSecret, resolveLedgerSigningSecret } from './config.js';

export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const DEFAULT_LEDGER_DIR = path.resolve(process.cwd(), '.vigilante/ledger');
const DEFAULT_LOCK_TIMEOUT_MS = 10000;
const DEFAULT_LOCK_STALE_MS = 30000;
const ledgerLocks = new Map();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function timingSafeEqualString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

async function acquireOsLedgerLock(ledgerDir, options = {}) {
  await fs.mkdir(ledgerDir, { recursive: true, mode: 0o700 });
  await fs.chmod(ledgerDir, 0o700).catch(() => {});

  const lockPath = path.join(ledgerDir, '.ledger.lock');
  const timeoutMs = Number.isFinite(options.lockTimeoutMs) && options.lockTimeoutMs > 0
    ? options.lockTimeoutMs
    : DEFAULT_LOCK_TIMEOUT_MS;
  const staleMs = Number.isFinite(options.lockStaleMs) && options.lockStaleMs > 0
    ? options.lockStaleMs
    : DEFAULT_LOCK_STALE_MS;
  const openFlags = fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | (fsConstants.O_NOFOLLOW || 0);
  const deadline = Date.now() + timeoutMs;

  while (true) {
    let handle;
    try {
      handle = await fs.open(lockPath, openFlags, 0o600);
      await handle.chmod(0o600).catch(() => {});
      const lockStat = await handle.stat();
      await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: Date.now() }), 'utf8');
      await handle.close();
      handle = null;

      return async () => {
        try {
          const curStat = await fs.lstat(lockPath);
          if (curStat.ino === lockStat.ino && curStat.dev === lockStat.dev) {
            await fs.unlink(lockPath);
          }
        } catch {
          // Already removed
        }
      };
    } catch (err) {
      if (handle) {
        await handle.close().catch(() => {});
      }
      if (!err || (err.code !== 'EEXIST' && err.code !== 'ELOOP')) {
        throw err;
      }

      try {
        const st = await fs.lstat(lockPath);
        if (st.isSymbolicLink()) {
          throw new Error(`Refusing symlink ledger lockfile '${lockPath}'`);
        }
        if (Date.now() - st.mtimeMs > staleMs) {
          await fs.unlink(lockPath).catch(() => {});
          continue;
        }
      } catch (statErr) {
        if (statErr && statErr.code === 'ENOENT') {
          continue;
        }
        if (statErr && !statErr.code) {
          throw statErr;
        }
      }

      if (Date.now() >= deadline) {
        throw new Error(`Timed out acquiring ledger lockfile '${lockPath}' after ${timeoutMs}ms`);
      }
      await sleep(10 + Math.floor(Math.random() * 15));
    }
  }
}

function withLedgerLock(ledgerDir, fn, options = {}) {
  const key = path.resolve(ledgerDir);
  const prev = ledgerLocks.get(key) || Promise.resolve();
  const run = async () => {
    const release = await acquireOsLedgerLock(ledgerDir, options);
    try {
      return await fn();
    } finally {
      await release();
    }
  };
  const next = prev.then(run, run);
  const settled = next.catch(() => {});
  ledgerLocks.set(key, settled);
  return next.finally(() => {
    if (ledgerLocks.get(key) === settled) {
      ledgerLocks.delete(key);
    }
  });
}

/**
 * Deterministic SHA-256 hash helper
 * @param {string|Buffer|Object} data 
 * @returns {string} Hex-encoded SHA-256
 */
export function hashData(data) {
  const buf = typeof data === 'string' 
    ? Buffer.from(data, 'utf8') 
    : Buffer.isBuffer(data) 
      ? data 
      : Buffer.from(JSON.stringify(data), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Compute deterministic hash for a ledger entry structure
 * @param {Object} entry 
 * @returns {string}
 */
export function calculateEntryHash(entry) {
  const signer = entry.signer && typeof entry.signer === 'object'
    ? {
        id: entry.signer.id || 'anonymous',
        role: entry.signer.role || '',
        keyId: entry.signer.keyId || ''
      }
    : { id: 'anonymous', role: '', keyId: '' };
  const canonicalData = {
    index: entry.index,
    timestamp: entry.timestamp,
    entryType: entry.entryType,
    payloadHash: hashData(entry.payload),
    prevHash: entry.prevHash,
    signer
  };
  return hashData(canonicalData);
}

/**
 * Initialize append-only audit ledger
 * @param {string} ledgerDir 
 * @param {Object} options 
 * @returns {Promise<Object>}
 */
export async function initAuditLedger(ledgerDir = DEFAULT_LEDGER_DIR, options = {}) {
  await fs.mkdir(ledgerDir, { recursive: true, mode: 0o700 });
  await fs.chmod(ledgerDir, 0o700).catch(() => {});
  const ledgerFile = path.join(ledgerDir, 'ledger.jsonl');
  const metaFile = path.join(ledgerDir, 'metadata.json');

  let entryCount = 0;
  let lastHash = GENESIS_PREV_HASH;

  if (fsSync.existsSync(ledgerFile)) {
    await fs.chmod(ledgerFile, 0o600);
    const lines = (await fs.readFile(ledgerFile, 'utf8')).trim().split('\n').filter(Boolean);
    entryCount = lines.length;
    if (entryCount > 0) {
      try {
        const lastEntry = JSON.parse(lines[lines.length - 1]);
        lastHash = lastEntry.entryHash || GENESIS_PREV_HASH;
      } catch (err) {
        logger.warn(`Ledger initialization: error parsing last line: ${err.message}`);
      }
    }
  } else {
    await fs.writeFile(ledgerFile, '', { encoding: 'utf8', mode: 0o600 });
    await fs.chmod(ledgerFile, 0o600);
  }

  const metadata = {
    initializedAt: new Date().toISOString(),
    ledgerDir,
    ledgerFile,
    entryCount,
    lastHash,
    genesisHash: GENESIS_PREV_HASH,
    cipherSuite: 'SHA256-HMAC-MERKLE-V1'
  };

  if (!fsSync.existsSync(metaFile)) {
    await fs.writeFile(metaFile, JSON.stringify(metadata, null, 2), { encoding: 'utf8', mode: 0o600 });
  }
  await fs.chmod(metaFile, 0o600);

  return metadata;
}

/**
 * Read all entries from ledger directory
 * @param {string} ledgerDir 
 * @returns {Promise<Array<Object>>}
 */
export async function getLedgerEntries(ledgerDir = DEFAULT_LEDGER_DIR) {
  const ledgerFile = path.join(ledgerDir, 'ledger.jsonl');
  if (!fsSync.existsSync(ledgerFile)) {
    return [];
  }
  const content = await fs.readFile(ledgerFile, 'utf8');
  const lines = content.trim().split('\n').filter(Boolean);
  return lines.map(line => JSON.parse(line));
}

/**
 * Append an immutable entry to the ledger
 * @param {string} entryType - e.g. 'INCIDENT_VERDICT', 'CONTAINMENT_ACTION', 'FORENSIC_CAPTURE'
 * @param {Object|string} payload - Evidence, alert, or action record
 * @param {Object} signerInfo - Signer identity and role
 * @param {Object} options - { ledgerDir, signingSecret }
 * @returns {Promise<Object>} The signed and chained entry
 */
export async function appendLedgerEntry(entryType, payload, signerInfo = {}, options = {}) {
  const ledgerDir = options.ledgerDir || DEFAULT_LEDGER_DIR;
  return withLedgerLock(ledgerDir, async () => {
    await fs.mkdir(ledgerDir, { recursive: true, mode: 0o700 });
    await fs.chmod(ledgerDir, 0o700).catch(() => {});
    const ledgerFile = path.join(ledgerDir, 'ledger.jsonl');

    const existingEntries = await getLedgerEntries(ledgerDir);
    const index = existingEntries.length;
    const prevHash = index === 0 ? GENESIS_PREV_HASH : existingEntries[index - 1].entryHash;

    const signer = {
      id: signerInfo.id || 'agent:vigilante-soar',
      role: signerInfo.role || 'IncidentCommander',
      keyId: signerInfo.keyId || 'secp256k1-local'
    };

    const draftEntry = {
      index,
      timestamp: new Date().toISOString(),
      entryType: String(entryType || 'GENERIC_AUDIT'),
      payload,
      signer,
      prevHash
    };

    const entryHash = calculateEntryHash(draftEntry);
    // Fail closed: an entry signed with a source-shipped default secret is
    // forgeable by anyone, so refuse to append without a provisioned key.
    const secret = requireLedgerSigningSecret(options.signingSecret);
    const signature = crypto.createHmac('sha256', secret).update(entryHash).digest('hex');

    const finalEntry = {
      ...draftEntry,
      entryHash,
      signature
    };

    await fs.appendFile(ledgerFile, JSON.stringify(finalEntry) + '\n', { mode: 0o600, encoding: 'utf8' });
    await fs.chmod(ledgerFile, 0o600);
    return finalEntry;
  }, options);
}

function getRawLeafValue(entry) {
  if (typeof entry === 'string') return entry;
  return entry.entryHash || hashData(entry);
}

/**
 * RFC 6962 domain-separated leaf hash: SHA-256(0x00 || leaf)
 */
function hashMerkleLeaf(rawLeaf) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(String(rawLeaf), 'utf8')]))
    .digest('hex');
}

/**
 * RFC 6962 domain-separated internal node hash: SHA-256(0x01 || left || right)
 */
function hashMerkleNode(leftHash, rightHash) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(String(leftHash), 'utf8'), Buffer.from(String(rightHash), 'utf8')]))
    .digest('hex');
}

/**
 * Build balanced binary Merkle tree (RFC 6962 domain separation, odd node promotion)
 * and calculate Merkle root.
 * @param {Array<Object|string>} entries - List of entries or hashes
 * @returns {{ root: string|null, leafCount: number, treeLevels: Array<Array<string>> }}
 */
export function buildMerkleRoot(entries = []) {
  if (!entries || entries.length === 0) {
    return { root: null, leafCount: 0, treeLevels: [] };
  }

  // Domain-separated leaf hashes (0x00 prefix)
  let currentLevel = entries.map(e => hashMerkleLeaf(getRawLeafValue(e)));

  const treeLevels = [currentLevel.slice()];

  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        nextLevel.push(hashMerkleNode(currentLevel[i], currentLevel[i + 1]));
      } else {
        // Promote odd trailing node directly without duplicating it (prevents CVE-2012-2459)
        nextLevel.push(currentLevel[i]);
      }
    }
    treeLevels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    root: currentLevel[0] || null,
    leafCount: entries.length,
    treeLevels
  };
}

/**
 * Generate cryptographic Merkle inclusion audit proof for an entry index
 * @param {number} entryIndex 
 * @param {Array<Object|string>} entries 
 * @returns {{ entryIndex: number, entryHash: string, proof: Array<Object>, root: string }}
 */
export function generateInclusionProof(entryIndex, entries = []) {
  if (entryIndex < 0 || entryIndex >= entries.length) {
    throw new Error(`Invalid entryIndex: ${entryIndex}, entries length: ${entries.length}`);
  }

  const { root, treeLevels } = buildMerkleRoot(entries);
  const targetHash = getRawLeafValue(entries[entryIndex]);

  const proof = [];
  let idx = entryIndex;

  // Traverse tree levels from leaves up to root - 1
  for (let level = 0; level < treeLevels.length - 1; level++) {
    const nodes = treeLevels[level];
    const isRightNode = idx % 2 === 1;
    if (isRightNode) {
      proof.push({
        position: 'left',
        hash: nodes[idx - 1]
      });
    } else if (idx + 1 < nodes.length) {
      proof.push({
        position: 'right',
        hash: nodes[idx + 1]
      });
    }
    // Odd trailing node with no sibling was promoted directly to next level

    idx = Math.floor(idx / 2);
  }

  return {
    entryIndex,
    entryHash: targetHash,
    proof,
    root
  };
}

/**
 * Verify cryptographic inclusion proof against a known Merkle root
 * @param {string} entryHash 
 * @param {Array<{ position: 'left'|'right', hash: string }>} proof 
 * @param {string} merkleRoot 
 * @returns {boolean}
 */
export function verifyInclusionProof(entryHash, proof = [], merkleRoot) {
  if (!entryHash || !merkleRoot) return false;

  let currentHash = hashMerkleLeaf(entryHash);
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string' || (step.position !== 'left' && step.position !== 'right')) {
      return false;
    }
    if (step.position === 'right') {
      currentHash = hashMerkleNode(currentHash, step.hash);
    } else {
      currentHash = hashMerkleNode(step.hash, currentHash);
    }
  }

  return timingSafeEqualString(currentHash, merkleRoot);
}

/**
 * Traverse the entire ledger chain and verify cryptographic integrity
 * @param {string} ledgerDir 
 * @param {Object} options 
 * @returns {Promise<{ valid: boolean, count: number, merkleRoot: string|null, lastHash: string, issue?: string }>}
 */
export async function verifyLedgerIntegrity(ledgerDir = DEFAULT_LEDGER_DIR, options = {}) {
  const entries = await getLedgerEntries(ledgerDir);
  if (entries.length === 0) {
    return { valid: true, count: 0, merkleRoot: null, lastHash: GENESIS_PREV_HASH };
  }

  const secret = resolveLedgerSigningSecret(options.signingSecret);
  if (!secret) {
    return {
      valid: false,
      count: entries.length,
      merkleRoot: null,
      lastHash: entries[entries.length - 1].entryHash,
      issue: 'Ledger signing secret is not configured: entry signatures cannot be verified (set VIGILANTE_LEDGER_SECRET or ledger.signingSecret in config.yaml)'
    };
  }

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // Check index sequencing
    if (entry.index !== i) {
      return {
        valid: false,
        count: entries.length,
        corruptedIndex: i,
        issue: `Sequence gap: expected index ${i}, found ${entry.index}`
      };
    }

    // Check prevHash chain
    const expectedPrevHash = i === 0 ? GENESIS_PREV_HASH : entries[i - 1].entryHash;
    if (entry.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        count: entries.length,
        corruptedIndex: i,
        issue: `Broken hash chain at index ${i}: prevHash mismatch`
      };
    }

    // Verify recalculation of entryHash
    const recalculatedHash = calculateEntryHash(entry);
    if (entry.entryHash !== recalculatedHash) {
      return {
        valid: false,
        count: entries.length,
        corruptedIndex: i,
        issue: `Tampered entry content at index ${i}: entryHash mismatch`
      };
    }

    // Verify signature (constant-time comparison on equal-length Buffers)
    const expectedSig = crypto.createHmac('sha256', secret).update(entry.entryHash).digest('hex');
    if (!timingSafeEqualString(entry.signature, expectedSig)) {
      return {
        valid: false,
        count: entries.length,
        corruptedIndex: i,
        issue: `Invalid cryptographic signature at index ${i}`
      };
    }
  }

  const { root } = buildMerkleRoot(entries);
  return {
    valid: true,
    count: entries.length,
    merkleRoot: root,
    lastHash: entries[entries.length - 1].entryHash
  };
}

/**
 * Generate a court-admissible Legal Chain-of-Custody Report
 * @param {string} incidentId 
 * @param {string} ledgerDir 
 * @param {Object} [options={}]
 * @returns {Promise<{ incidentId: string, markdown: string, entries: Array<Object>, merkleRoot: string }>}
 */
export async function exportLegalChainOfCustody(incidentId, ledgerDir = DEFAULT_LEDGER_DIR, options = {}) {
  if (!incidentId || typeof incidentId !== 'string') {
    throw new Error('Valid incidentId is required to export legal chain of custody');
  }

  const integrity = await verifyLedgerIntegrity(ledgerDir, options);
  if (!integrity.valid) {
    throw new Error(`Refusing chain-of-custody export: ledger integrity verification failed (${integrity.issue || 'tampered ledger'})`);
  }

  const entries = await getLedgerEntries(ledgerDir);
  const relevant = entries.filter(e =>
    Boolean(e.payload && typeof e.payload === 'object' && e.payload.incidentId === incidentId)
  );

  const targetEntries = relevant;
  const { root } = buildMerkleRoot(targetEntries);

  const markdown = [
    `# ⚖️ LEGAL CHAIN-OF-CUSTODY AUDIT AFFIDAVIT`,
    `**Incident Reference:** \`${incidentId}\``,
    `**Generated:** ${new Date().toISOString()}`,
    `**Cryptographic Merkle Root:** \`${root}\``,
    `**Total Evidence Entries:** ${targetEntries.length}`,
    ``,
    `## Cryptographic Verification Statement`,
    `The digital records below have been recorded in an append-only, SHA-256 hash-chained cryptographic ledger. Each record is verified with an HMAC digital signature and chained to its predecessor. No records have been altered, backdated, or omitted.`,
    ``,
    `| Index | Timestamp (UTC) | Type | Signer | Hash Checkpoint |`,
    `| :--- | :--- | :--- | :--- | :--- |`,
    ...targetEntries.map(e => `| \`#${e.index}\` | ${e.timestamp} | \`${e.entryType}\` | ${e.signer.role} (${e.signer.id}) | \`${e.entryHash.slice(0, 16)}...\` |`),
    ``,
    `## Merkle Proof Verification`,
    `Each individual evidence entry can be independently verified against Merkle Root \`${root}\` without disclosing unredacted sibling metadata.`,
    ``,
    `---\n*Certified by VIGILANTE Autonomous Security Operating Center*`
  ].join('\n');

  return {
    incidentId,
    markdown,
    entries: targetEntries,
    merkleRoot: root
  };
}
