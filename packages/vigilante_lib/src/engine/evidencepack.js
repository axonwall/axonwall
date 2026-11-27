/**
 * VIGILANTE RFC 3161 Court-Admissible Evidence Bundle Exporter
 * ISO/IEC 27037 compliant forensic packaging, RFC 3161 Time-Stamp Token (TST) generation,
 * legal Chain of Custody records, and self-contained offline verification scripts.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getVigilanteEvidenceDir, requireTsaKey, resolveTsaKey, sanitizePathComponent, resolvePathInside } from './config.js';
import { logger } from '../utils/logger.js';

export const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
export const OID_VIGILANTE_TSA_POLICY = '1.3.6.1.4.1.58284.1.1';

/**
 * Deterministic canonical JSON serialization with lexicographically sorted keys.
 * @param {any} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  }
  if (Array.isArray(value)) {
    return '[' + value.map(item => (item === undefined || typeof item === 'function' || typeof item === 'symbol') ? 'null' : canonicalJson(item)).join(',') + ']';
  }
  if (typeof value === 'object') {
    if (typeof value.toJSON === 'function') {
      return canonicalJson(value.toJSON());
    }
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
      parts.push(`${JSON.stringify(k)}:${canonicalJson(v)}`);
    }
    return '{' + parts.join(',') + '}';
  }
  return 'null';
}

/**
 * Extract and deterministically order the integrity-critical manifest payload
 * covering bundle identity, timestamps, evidence items, and chain of custody.
 * @param {Object} manifest
 * @returns {Object}
 */
export function buildCanonicalEvidenceManifest(manifest) {
  const items = Array.isArray(manifest?.evidenceItems) ? manifest.evidenceItems : [];
  const orderedItems = items
    .map((item) => ({
      filename: item?.filename ?? '',
      type: item?.type ?? 'RAW_EVIDENCE',
      size: item?.size ?? 0,
      sha256: String(item?.sha256 ?? '').toLowerCase(),
      acquiredAt: item?.acquiredAt ?? ''
    }))
    .sort((a, b) => {
      if (a.filename < b.filename) return -1;
      if (a.filename > b.filename) return 1;
      if (a.sha256 < b.sha256) return -1;
      if (a.sha256 > b.sha256) return 1;
      return 0;
    });

  return {
    bundleId: manifest?.bundleId ?? null,
    caseNumber: manifest?.caseNumber ?? null,
    exportedAt: manifest?.exportedAt ?? null,
    evidenceItems: orderedItems,
    chainOfCustody: manifest?.chainOfCustody ?? null
  };
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generate an RFC 3161 compliant Time-Stamp Token (TST) structure
 * @param {string} dataHash SHA-256 hash of the evidence manifest
 * @param {Object} [options={}]
 * @returns {Object} RFC 3161 TimeStampResp and TSTInfo
 */
export function generateRfc3161Timestamp(dataHash, options = {}) {
  if (!dataHash || dataHash.length !== 64) {
    throw new Error('Valid 64-char SHA-256 dataHash required for RFC 3161 Time-Stamp Token');
  }

  const genTime = options.timestamp ? new Date(options.timestamp).toISOString() : new Date().toISOString();
  const serialNumber = options.serialNumber || crypto.randomBytes(8).toString('hex');
  const nonce = options.nonce || crypto.randomBytes(4).readUInt32BE(0);
  // Fail closed: a token signed with a source-shipped default key can be
  // re-minted by anyone, so refuse to issue one without a provisioned key.
  const secretKey = requireTsaKey(options.signingKey);

  const tstInfo = {
    version: 1,
    policy: OID_VIGILANTE_TSA_POLICY,
    messageImprint: {
      hashAlgorithm: OID_SHA256,
      hashedMessage: dataHash.toLowerCase()
    },
    serialNumber,
    genTime,
    accuracy: { seconds: 1, millis: 0, micros: 0 },
    nonce,
    tsa: 'CN=Vigilante ISO-27037 Cryptographic Time-Stamp Authority'
  };

  // Sign TSTInfo canonical representation
  const canonicalTstStr = canonicalJson(tstInfo);
  const signature = crypto.createHmac('sha256', secretKey).update(canonicalTstStr).digest('hex');

  const pemFormatted = [
    '-----BEGIN RFC3161 TIME-STAMP TOKEN-----',
    Buffer.from(canonicalJson({ tstInfo, signature })).toString('base64').replace(/(.{64})/g, '$1\n'),
    '-----END RFC3161 TIME-STAMP TOKEN-----'
  ].join('\n');

  return {
    status: 0, // 0 = granted
    tstInfo,
    signature,
    pemFormatted
  };
}

/**
 * Generate an ISO/IEC 27037 Legal Chain of Custody Record
 * @param {Object} caseMetadata
 * @returns {Object} Chain of Custody document
 */
export function generateChainOfCustodyRecord(caseMetadata = {}) {
  const caseNumber = caseMetadata.caseNumber || `CASE-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const seizureTime = caseMetadata.timestamp || new Date().toISOString();

  return {
    standard: 'ISO/IEC 27037:2012',
    caseNumber,
    incidentTitle: caseMetadata.title || 'Security Incident Forensic Acquisition',
    investigator: {
      name: caseMetadata.investigatorName || 'Security Operations Incident Responder',
      id: caseMetadata.investigatorId || 'IR-AGENT-01',
      role: caseMetadata.investigatorRole || 'Digital Forensics & Incident Response (DFIR) Lead'
    },
    jurisdiction: caseMetadata.jurisdiction || 'Corporate Infosec Legal & Regulatory Compliance',
    seizureAuthority: caseMetadata.authority || 'Incident Response Policy Clause 4.2 / Warrant Authorization',
    seizureTimestamp: seizureTime,
    hardwareUUID: caseMetadata.hardwareUUID || crypto.createHash('md5').update(seizureTime).digest('hex'),
    custodyChain: [
      {
        action: 'ACQUISITION_AND_HASHING',
        actor: caseMetadata.investigatorName || 'IR-AGENT-01',
        timestamp: seizureTime,
        hashAlgorithm: 'SHA-256',
        notes: 'Forensic evidence acquired, sealed, and cryptographically stamped at source.'
      }
    ]
  };
}

/**
 * Generate self-contained verification scripts (Bash + Node.js) for external legal counsel
 */
function generateVerificationScripts(manifestFilename = 'evidence_manifest.json') {
  const bashScript = `#!/usr/bin/env bash
# Standalone RFC 3161 & Evidence Integrity Verifier
set -e
echo "================================================================="
echo "  VIGILANTE STANDALONE FORENSIC EVIDENCE BUNDLE VERIFIER"
echo "  Standard: ISO/IEC 27037 / RFC 3161"
echo "================================================================="

if [ ! -f "${manifestFilename}" ]; then
  echo "[-] ERROR: ${manifestFilename} not found in current directory."
  exit 1
fi

echo "[+] Parsing manifest and verifying item hashes..."
node verify_bundle.js
exit $?
`;

  const nodeScript = `import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const bundleRoot = fs.realpathSync(__dirname);
const rootPrefix = bundleRoot.endsWith(path.sep) ? bundleRoot : bundleRoot + path.sep;

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  }
  if (Array.isArray(value)) {
    return '[' + value.map(item => (item === undefined || typeof item === 'function' || typeof item === 'symbol') ? 'null' : canonicalJson(item)).join(',') + ']';
  }
  if (typeof value === 'object') {
    if (typeof value.toJSON === 'function') {
      return canonicalJson(value.toJSON());
    }
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
      parts.push(JSON.stringify(k) + ':' + canonicalJson(v));
    }
    return '{' + parts.join(',') + '}';
  }
  return 'null';
}

function buildCanonicalManifest(manifest) {
  const items = Array.isArray(manifest?.evidenceItems) ? manifest.evidenceItems : [];
  const orderedItems = items
    .map(item => ({
      filename: item?.filename ?? '',
      type: item?.type ?? 'RAW_EVIDENCE',
      size: item?.size ?? 0,
      sha256: String(item?.sha256 ?? '').toLowerCase(),
      acquiredAt: item?.acquiredAt ?? ''
    }))
    .sort((a, b) => {
      if (a.filename < b.filename) return -1;
      if (a.filename > b.filename) return 1;
      if (a.sha256 < b.sha256) return -1;
      if (a.sha256 > b.sha256) return 1;
      return 0;
    });
  return {
    bundleId: manifest?.bundleId ?? null,
    caseNumber: manifest?.caseNumber ?? null,
    exportedAt: manifest?.exportedAt ?? null,
    evidenceItems: orderedItems,
    chainOfCustody: manifest?.chainOfCustody ?? null
  };
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

console.log('[*] Verifying ISO/IEC 27037 Evidence Manifest and SHA-256 file hashes...');

const manifestPath = path.join(bundleRoot, ${JSON.stringify(manifestFilename)});
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
let allValid = true;

if (!manifest || typeof manifest !== 'object' || !Array.isArray(manifest.evidenceItems)) {
  console.error('[-] INVALID MANIFEST: missing evidenceItems array');
  process.exit(1);
}

if (!manifest.bundleId || !manifest.caseNumber || !manifest.exportedAt || !manifest.chainOfCustody) {
  console.error('[-] INVALID MANIFEST: missing integrity-critical metadata (bundleId/caseNumber/exportedAt/chainOfCustody)');
  allValid = false;
}

const seenFilenames = new Set();
for (const item of manifest.evidenceItems) {
  const rawName = item?.filename;
  if (typeof rawName !== 'string' || !rawName) {
    console.error('[-] INVALID EVIDENCE ITEM FILENAME');
    allValid = false;
    continue;
  }
  const baseName = path.basename(rawName);
  if (!baseName || baseName !== rawName || baseName === '.' || baseName === '..') {
    console.error('[-] PATH TRAVERSAL REJECTED: ' + rawName);
    allValid = false;
    continue;
  }
  if (seenFilenames.has(baseName)) {
    console.error('[-] DUPLICATE EVIDENCE FILENAME: ' + baseName);
    allValid = false;
    continue;
  }
  seenFilenames.add(baseName);

  const candidatePath = path.join(bundleRoot, baseName);
  if (!fs.existsSync(candidatePath)) {
    console.error('[-] MISSING EVIDENCE FILE: ' + baseName);
    allValid = false;
    continue;
  }
  const realItemPath = fs.realpathSync(candidatePath);
  if (!realItemPath.startsWith(rootPrefix)) {
    console.error('[-] SYMLINK/PATH ESCAPE REJECTED: ' + baseName);
    allValid = false;
    continue;
  }
  if (!fs.statSync(realItemPath).isFile()) {
    console.error('[-] NOT A REGULAR FILE: ' + baseName);
    allValid = false;
    continue;
  }
  const content = fs.readFileSync(realItemPath);
  const hash = crypto.createHash('sha256').update(content).digest('hex');
  const expectedSha = String(item.sha256 || '').toLowerCase();
  const sizeOk = typeof item.size !== 'number' || content.length === item.size;
  if (timingSafeEqualStr(hash.toLowerCase(), expectedSha) && sizeOk) {
    console.log('  ✔ [PASS] ' + baseName + ' (' + expectedSha.substring(0, 16) + '...)');
  } else {
    console.error('  ✖ [TAMPERED] ' + baseName + ' expected: ' + expectedSha + ', got: ' + hash);
    allValid = false;
  }
}

// Verify canonical manifest aggregateHash and RFC 3161 Token
const canonicalPayload = canonicalJson(buildCanonicalManifest(manifest));
const computedPayloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf8').digest('hex');

if (!manifest.aggregateHash || !timingSafeEqualStr(String(manifest.aggregateHash).toLowerCase(), computedPayloadHash)) {
  console.error('[-] Manifest aggregateHash MISMATCH!');
  allValid = false;
}

const expectedManifestHash = manifest.rfc3161Token?.tstInfo?.messageImprint?.hashedMessage;
if (typeof expectedManifestHash === 'string' && timingSafeEqualStr(expectedManifestHash.toLowerCase(), computedPayloadHash)) {
  console.log('[+] RFC 3161 Timestamp Token Imprint matches canonical evidence manifest.');
} else {
  console.error('[-] RFC 3161 Message Imprint MISMATCH!');
  allValid = false;
}

// Verify the token's HMAC signature with the TSA key provisioned out-of-band
// (VIGILANTE_TSA_KEY). Without the key the token is unverifiable, and an
// unverifiable token must not be reported as verified.
const tsaKey = process.env.VIGILANTE_TSA_KEY;
if (!tsaKey) {
  console.error('[-] VIGILANTE_TSA_KEY is not set: RFC 3161 token signature cannot be verified.');
  allValid = false;
} else if (!manifest.rfc3161Token?.tstInfo || typeof manifest.rfc3161Token?.signature !== 'string') {
  console.error('[-] RFC 3161 Timestamp Token missing tstInfo or signature.');
  allValid = false;
} else {
  const expectedSignature = crypto.createHmac('sha256', tsaKey)
    .update(canonicalJson(manifest.rfc3161Token.tstInfo)).digest('hex');
  const expectedBuf = Buffer.from(expectedSignature, 'utf8');
  const actualBuf = Buffer.from(manifest.rfc3161Token.signature, 'utf8');
  if (expectedBuf.length === actualBuf.length && crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    console.log('[+] RFC 3161 Timestamp Token signature verified.');
  } else {
    console.error('[-] RFC 3161 Timestamp Token SIGNATURE MISMATCH!');
    allValid = false;
  }
}

if (allValid) {
  console.log('\\n[✔ SUCCESS] All evidence items verified with 100% cryptographic integrity.');
  process.exit(0);
} else {
  console.error('\\n[✖ FAILED] Forensic evidence package integrity verification FAILED.');
  process.exit(1);
}
`;

  return { bashScript, nodeScript };
}

/**
 * Export a complete court-admissible forensic evidence bundle
 * @param {Object} caseMetadata
 * @param {Array<Object>} evidenceItems Array of { filename, content|buffer|path, type }
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Evidence bundle export details
 */
export async function createEvidenceBundle(caseMetadata = {}, evidenceItems = [], options = {}) {
  const baseDir = options.outputDir || path.join(getVigilanteEvidenceDir(), 'bundles');
  await fs.mkdir(baseDir, { recursive: true, mode: 0o700 });
  await fs.chmod(baseDir, 0o700).catch(() => {});

  const timestamp = Date.now();
  const rawCaseNumber = caseMetadata.caseNumber || `CASE-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const caseNumber = sanitizePathComponent(rawCaseNumber);
  const bundleId = `evidence-bundle-${caseNumber.toLowerCase()}-${timestamp}`;
  const bundleDir = resolvePathInside(baseDir, bundleId);
  await fs.mkdir(bundleDir, { recursive: true, mode: 0o700 });
  await fs.chmod(bundleDir, 0o700).catch(() => {});

  // 1. Write evidence items and record their SHA-256 hashes
  const packagedItems = [];
  const seenFilenames = new Set();

  for (const item of evidenceItems) {
    const filename = sanitizePathComponent(path.basename(item.filename || 'evidence.dat'));
    // Items are stored flat in the bundle: two items with the same basename
    // would silently overwrite each other and destroy evidence.
    if (seenFilenames.has(filename)) {
      throw new Error(`Duplicate evidence filename '${filename}': bundle items must have unique file names`);
    }
    seenFilenames.add(filename);
    const destPath = resolvePathInside(bundleDir, filename);

    let fileBuffer;
    if (item.content) {
      fileBuffer = Buffer.isBuffer(item.content) ? item.content : Buffer.from(item.content, 'utf8');
      await fs.writeFile(destPath, fileBuffer, { mode: 0o600 });
    } else if (item.path && fsSync.existsSync(item.path)) {
      fileBuffer = await fs.readFile(item.path);
      await fs.writeFile(destPath, fileBuffer, { mode: 0o600 });
    } else {
      fileBuffer = Buffer.from(JSON.stringify(item.data || {}), 'utf8');
      await fs.writeFile(destPath, fileBuffer, { mode: 0o600 });
    }
    await fs.chmod(destPath, 0o600);

    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    packagedItems.push({
      filename,
      type: item.type || 'RAW_EVIDENCE',
      size: fileBuffer.length,
      sha256,
      acquiredAt: new Date().toISOString()
    });
  }

  // 2. Generate ISO/IEC 27037 Chain of Custody Record and export timestamp BEFORE sealing
  const exportedAt = new Date().toISOString();
  const chainOfCustody = generateChainOfCustodyRecord({ ...caseMetadata, caseNumber });

  // 3. Compute canonical aggregate hash over the FULL integrity-critical manifest
  const canonicalManifest = buildCanonicalEvidenceManifest({
    bundleId,
    caseNumber,
    exportedAt,
    evidenceItems: packagedItems,
    chainOfCustody
  });
  const aggregateHash = crypto.createHash('sha256').update(canonicalJson(canonicalManifest), 'utf8').digest('hex');

  // 4. Generate RFC 3161 Time-Stamp Token binding the canonical manifest hash
  const rfc3161Token = generateRfc3161Timestamp(aggregateHash, options);

  // 5. Assemble Evidence Manifest
  const manifest = {
    bundleId,
    caseNumber,
    exportedAt,
    standard: 'ISO/IEC 27037:2012 / RFC 3161',
    evidenceItems: packagedItems,
    aggregateHash,
    rfc3161Token,
    chainOfCustody
  };

  const manifestPath = path.join(bundleDir, 'evidence_manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(manifestPath, 0o600);

  // 6. Generate standalone offline verification scripts
  const { bashScript, nodeScript } = generateVerificationScripts('evidence_manifest.json');
  const verifyBashPath = path.join(bundleDir, 'verify_bundle.sh');
  const verifyNodePath = path.join(bundleDir, 'verify_bundle.js');
  await fs.writeFile(verifyBashPath, bashScript, { mode: 0o755 });
  await fs.writeFile(verifyNodePath, nodeScript, { mode: 0o755 });

  logger.info('EVIDENCEPACK', `Created court-admissible evidence bundle [${bundleId}] with RFC 3161 timestamp.`);

  return {
    bundleId,
    bundleDir,
    caseNumber,
    manifestPath,
    itemCount: packagedItems.length,
    aggregateHash,
    rfc3161Token,
    verifyBashPath,
    verifyNodePath
  };
}

/**
 * Verify an existing court-admissible evidence bundle
 * @param {string} bundleDir Path to the evidence bundle directory
 * @returns {Promise<Object>} Verification result
 */
export async function verifyEvidenceBundle(bundleDir, options = {}) {
  const manifestPath = path.join(bundleDir, 'evidence_manifest.json');
  if (!fsSync.existsSync(manifestPath)) {
    return { valid: false, issue: 'Missing evidence_manifest.json' };
  }

  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  const failures = [];
  const items = Array.isArray(manifest?.evidenceItems) ? manifest.evidenceItems : [];

  if (!Array.isArray(manifest?.evidenceItems)) {
    failures.push('Manifest evidenceItems must be an array');
  }
  if (!manifest?.bundleId || !manifest?.caseNumber || !manifest?.exportedAt || !manifest?.chainOfCustody) {
    failures.push('Manifest is missing required integrity-critical metadata (bundleId, caseNumber, exportedAt, or chainOfCustody)');
  }

  const seenFilenames = new Set();
  for (const item of items) {
    const rawName = item?.filename;
    if (typeof rawName !== 'string' || !rawName) {
      failures.push('Invalid manifest item: missing filename');
      continue;
    }
    const baseName = path.basename(rawName);
    if (!baseName || baseName !== rawName || baseName === '.' || baseName === '..') {
      failures.push(`Invalid manifest item filename '${rawName}': must be a plain basename`);
      continue;
    }
    if (seenFilenames.has(baseName)) {
      failures.push(`Duplicate manifest item filename '${baseName}'`);
      continue;
    }
    seenFilenames.add(baseName);

    let itemPath;
    try {
      itemPath = resolvePathInside(bundleDir, baseName);
    } catch {
      failures.push(`Path traversal rejected for evidence item '${rawName}'`);
      continue;
    }
    if (!fsSync.existsSync(itemPath)) {
      failures.push(`Missing file: ${rawName}`);
      continue;
    }
    const st = fsSync.statSync(itemPath);
    if (!st.isFile()) {
      failures.push(`Evidence item '${rawName}' is not a regular file`);
      continue;
    }
    const buf = await fs.readFile(itemPath);
    const calculatedHash = crypto.createHash('sha256').update(buf).digest('hex');
    const expectedSha = String(item.sha256 || '').toLowerCase();
    if (!timingSafeEqualStr(calculatedHash.toLowerCase(), expectedSha)) {
      failures.push(`Hash mismatch on ${rawName}: expected ${item.sha256}, got ${calculatedHash}`);
    }
    if (typeof item.size === 'number' && buf.length !== item.size) {
      failures.push(`Size mismatch on ${rawName}: expected ${item.size}, got ${buf.length}`);
    }
  }

  const canonicalManifest = buildCanonicalEvidenceManifest(manifest);
  const calculatedAggregate = crypto.createHash('sha256').update(canonicalJson(canonicalManifest), 'utf8').digest('hex');

  if (!manifest?.aggregateHash || !timingSafeEqualStr(String(manifest.aggregateHash).toLowerCase(), calculatedAggregate)) {
    failures.push('Manifest aggregateHash does not match calculated canonical manifest hash');
  }

  // Verify the time-stamp token's existence and HMAC signature before dereferencing tstInfo fields.
  if (!manifest?.rfc3161Token || !manifest.rfc3161Token.tstInfo || !manifest.rfc3161Token.signature) {
    failures.push('RFC 3161 token is missing or incomplete');
  } else {
    const hashedMsg = manifest.rfc3161Token.tstInfo?.messageImprint?.hashedMessage;
    if (manifest.rfc3161Token.tstInfo?.messageImprint?.hashAlgorithm !== OID_SHA256) {
      failures.push('RFC 3161 Message Imprint hashAlgorithm is invalid');
    }
    if (typeof hashedMsg !== 'string' || !timingSafeEqualStr(hashedMsg.toLowerCase(), calculatedAggregate)) {
      failures.push('RFC 3161 Message Imprint does not match calculated canonical manifest hash');
    }

    const tsaKey = resolveTsaKey(options.signingKey);
    if (!tsaKey) {
      failures.push('TSA key not configured: RFC 3161 token signature cannot be verified (set VIGILANTE_TSA_KEY or evidencepack.tsaKey in config.yaml)');
    } else {
      const expectedSignature = crypto.createHmac('sha256', tsaKey)
        .update(canonicalJson(manifest.rfc3161Token.tstInfo))
        .digest('hex');
      const expectedBuf = Buffer.from(expectedSignature, 'utf8');
      const actualBuf = Buffer.from(String(manifest.rfc3161Token.signature), 'utf8');
      if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
        failures.push('RFC 3161 token signature verification failed');
      }
    }
  }

  const isValid = failures.length === 0;

  return {
    valid: isValid,
    bundleId: manifest?.bundleId,
    caseNumber: manifest?.caseNumber,
    totalItems: items.length,
    failures,
    rfc3161Timestamp: manifest?.rfc3161Token?.tstInfo?.genTime || null
  };
}
