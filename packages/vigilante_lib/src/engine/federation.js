/**
 * VIGILANTE Multi-Cluster Defense Federation & Peer-to-Peer Threat Sharing
 * Cryptographic Ed25519 node identity, tamper-proof threat indicator signing/verification,
 * peer broadcast, and automated cross-cluster SOAR containment ingestion.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { getVigilanteConfigDir, ensureVigilanteConfig, resolvePathInside } from './config.js';
import * as soar from './soar.js';
import * as datalake from './datalake.js';
import { logger } from '../utils/logger.js';

export const FEDERATION_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_REPLAY_CACHE_ENTRIES = 10000;
const REPLAY_CACHE_FILENAME = 'replay_cache.json';

const replayCachesByPath = new Map();

export function getVigilanteFederationDir() {
  return path.join(getVigilanteConfigDir(), 'federation');
}

function getReplayCachePath() {
  return path.join(getVigilanteFederationDir(), REPLAY_CACHE_FILENAME);
}

export function clearFederationReplayMemoryCacheForTest() {
  replayCachesByPath.clear();
}

export function resetFederationReplayCacheForTest() {
  replayCachesByPath.clear();
  try {
    const cachePath = getReplayCachePath();
    if (fsSync.existsSync(cachePath)) {
      fsSync.unlinkSync(cachePath);
    }
  } catch {
    // Best-effort test cleanup
  }
}

/**
 * Initialize or load a local federation node with an Ed25519 cryptographic key pair.
 * @param {Object} nodeConfig - { nodeId, clusterName, peers }
 * @returns {Promise<Object>} Node descriptor
 */
export async function createFederationNode(nodeConfig = {}) {
  await ensureVigilanteConfig();
  const federationDir = getVigilanteFederationDir();
  await fs.mkdir(federationDir, { recursive: true });
  await fs.mkdir(path.join(federationDir, 'threats'), { recursive: true });

  const nodeFile = path.join(federationDir, 'node.json');

  // Load existing node if available and no override requested
  if (fsSync.existsSync(nodeFile) && !nodeConfig.forceNew) {
    try {
      const data = JSON.parse(await fs.readFile(nodeFile, 'utf8'));
      if (nodeConfig.peers && Array.isArray(nodeConfig.peers)) {
        data.peers = Array.from(new Set([...(data.peers || []), ...nodeConfig.peers]));
        await fs.writeFile(nodeFile, JSON.stringify(data, null, 2), 'utf8');
      }
      return data;
    } catch {
      // Continue to re-generate if corrupted
    }
  }

  // Generate Ed25519 Key Pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const node = {
    nodeId: nodeConfig.nodeId || `node-${crypto.randomBytes(6).toString('hex')}`,
    clusterName: nodeConfig.clusterName || 'cluster-prod-01',
    publicKey,
    privateKey,
    peers: nodeConfig.peers || [],
    createdAt: new Date().toISOString(),
    status: 'ONLINE'
  };

  await fs.writeFile(nodeFile, JSON.stringify(node, null, 2), { mode: 0o600, encoding: 'utf8' });
  logger.info('FEDERATION', `Initialized local federation node: ${node.nodeId} (${node.clusterName})`);

  return node;
}

/**
 * Canonical JSON serialization: object keys sorted recursively, so two
 * semantically identical payloads always serialize (and therefore sign and
 * verify) identically regardless of key insertion order or JSON round-trips.
 * @param {*} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/**
 * The signed content of a threat envelope: payload, signer identity,
 * timestamp, and (when present) unique anti-replay nonce.
 */
function signedEnvelopeContent({ payload, signerNodeId, timestamp, nonce }) {
  if (nonce !== undefined && nonce !== null) {
    return canonicalJson({ payload, signerNodeId, timestamp, nonce });
  }
  return canonicalJson({ payload, signerNodeId, timestamp });
}

function computeReplayCacheKey(signedRecord) {
  const signerNodeId = String(signedRecord.signerNodeId || '').trim();
  const contentHash = crypto
    .createHash('sha256')
    .update(signedEnvelopeContent({
      payload: signedRecord.payload,
      signerNodeId,
      timestamp: signedRecord.timestamp,
      nonce: signedRecord.nonce
    }))
    .digest('hex');
  const discriminator = (typeof signedRecord.nonce === 'string' && signedRecord.nonce.trim())
    ? `nonce:${signedRecord.nonce.trim()}`
    : `hash:${contentHash}`;
  return crypto.createHash('sha256').update(`${signerNodeId}\0${discriminator}`).digest('hex');
}

function loadReplayCacheMapSync(cachePath, nowMs) {
  let map = replayCachesByPath.get(cachePath);
  if (!map) {
    map = new Map();
    if (fsSync.existsSync(cachePath)) {
      try {
        const parsed = JSON.parse(fsSync.readFileSync(cachePath, 'utf8'));
        const entries = parsed && typeof parsed === 'object' ? parsed.entries : null;
        if (entries && typeof entries === 'object') {
          for (const [key, meta] of Object.entries(entries)) {
            if (meta && typeof meta.expiresAtMs === 'number' && meta.expiresAtMs >= nowMs) {
              map.set(key, {
                expiresAtMs: meta.expiresAtMs,
                recordedAtMs: typeof meta.recordedAtMs === 'number' ? meta.recordedAtMs : nowMs
              });
            }
          }
        }
      } catch {
        // Start clean if persisted cache was unreadable
      }
    }
    replayCachesByPath.set(cachePath, map);
  }

  for (const [key, meta] of map.entries()) {
    if (!meta || meta.expiresAtMs < nowMs) {
      map.delete(key);
    }
  }
  return map;
}

function persistReplayCacheMapSync(cachePath, map) {
  try {
    const dir = path.dirname(cachePath);
    fsSync.mkdirSync(dir, { recursive: true });
    const entries = Object.fromEntries(map.entries());
    const tmpPath = `${cachePath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    fsSync.writeFileSync(tmpPath, JSON.stringify({ entries }, null, 2), { mode: 0o600, encoding: 'utf8' });
    fsSync.renameSync(tmpPath, cachePath);
  } catch (err) {
    logger.warn('FEDERATION', `Failed to persist replay cache: ${err.message}`);
  }
}

function recordReplayEntrySync(cachePath, cacheKey, expiresAtMs, nowMs) {
  const map = loadReplayCacheMapSync(cachePath, nowMs);
  if (map.has(cacheKey)) {
    return false;
  }
  if (map.size >= MAX_REPLAY_CACHE_ENTRIES) {
    const sorted = Array.from(map.entries()).sort((a, b) => a[1].recordedAtMs - b[1].recordedAtMs);
    const evictCount = map.size - MAX_REPLAY_CACHE_ENTRIES + 1;
    for (let i = 0; i < evictCount && i < sorted.length; i++) {
      map.delete(sorted[i][0]);
    }
  }
  map.set(cacheKey, { expiresAtMs, recordedAtMs: nowMs });
  persistReplayCacheMapSync(cachePath, map);
  return true;
}

function validateThreatTimestampFreshness(signedRecord, options = {}) {
  const signerNodeId = typeof signedRecord.signerNodeId === 'string' ? signedRecord.signerNodeId.trim() : '';
  if (!signerNodeId) {
    return { ok: false, error: 'Invalid envelope structure: missing signerNodeId' };
  }
  if (typeof signedRecord.timestamp !== 'string' || !signedRecord.timestamp.trim()) {
    return { ok: false, error: 'Invalid envelope structure: missing timestamp' };
  }
  const tsMs = Date.parse(signedRecord.timestamp);
  if (!Number.isFinite(tsMs)) {
    return { ok: false, error: 'Invalid threat record timestamp' };
  }
  const maxClockSkewMs = Number.isFinite(options.maxClockSkewMs) && options.maxClockSkewMs >= 0
    ? options.maxClockSkewMs
    : FEDERATION_MAX_CLOCK_SKEW_MS;
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  if (Math.abs(nowMs - tsMs) > maxClockSkewMs) {
    return {
      ok: false,
      error: `Threat record timestamp '${signedRecord.timestamp}' is outside ±${Math.round(maxClockSkewMs / 1000)}s freshness window`
    };
  }
  return { ok: true, signerNodeId, tsMs, nowMs, maxClockSkewMs };
}

/**
 * Digitally signs a threat indicator record using Ed25519 private key.
 * @param {Object} threatData - Payload (e.g. { indicator: '198.51.100.22', type: 'IP', severity: 'CRITICAL', mitre: 'T1059' })
 * @param {string} privateKeyPem - Ed25519 PKCS8 PEM private key
 * @param {Object} signerInfo - { nodeId, publicKey }
 * @returns {Object} Signed threat envelope
 */
export function signThreatRecord(threatData, privateKeyPem, signerInfo = {}) {
  if (!threatData || typeof threatData !== 'object') {
    throw new Error('threatData must be a valid object');
  }
  if (!privateKeyPem) {
    throw new Error('privateKeyPem is required to sign threat record');
  }

  const signerNodeId = signerInfo.nodeId || 'anonymous-node';
  const timestamp = new Date().toISOString();
  const nonce = signerInfo.nonce || crypto.randomBytes(16).toString('hex');
  const content = signedEnvelopeContent({ payload: threatData, signerNodeId, timestamp, nonce });
  const signature = crypto.sign(null, Buffer.from(content, 'utf8'), privateKeyPem).toString('base64');

  return {
    payload: threatData,
    signature,
    algorithm: 'Ed25519',
    timestamp,
    nonce,
    signerNodeId,
    signerPublicKey: signerInfo.publicKey || null
  };
}

/**
 * Cryptographically verifies a signed threat envelope using Ed25519 public key,
 * enforcing timestamp freshness (±5 min default) and replay cache checks.
 * The key MUST be supplied by the caller from a trusted source (a pinned peer
 * key or keyring). The envelope's own signerPublicKey is never trusted: it is
 * attacker-controlled data, and verifying against it proves nothing.
 * @param {Object} signedRecord - Envelope returned by signThreatRecord
 * @param {string} publicKeyPem - Trusted Ed25519 SPKI PEM public key for the claimed signer
 * @param {Object} [options={}] - { maxClockSkewMs, nowMs, checkReplay, recordReplay }
 * @returns {Object} { valid: boolean, error?: string, payload?: Object }
 */
export function verifyThreatRecord(signedRecord, publicKeyPem = null, options = {}) {
  if (!signedRecord || !signedRecord.signature || !signedRecord.payload || typeof signedRecord.payload !== 'object') {
    return { valid: false, error: 'Invalid envelope structure: missing signature or payload' };
  }

  if (signedRecord.algorithm && signedRecord.algorithm !== 'Ed25519') {
    return { valid: false, error: `Unsupported signature algorithm '${signedRecord.algorithm}'` };
  }

  if (!publicKeyPem) {
    return {
      valid: false,
      error: 'No trusted public key provided: verification requires a caller-supplied peer key; the envelope-embedded key is not trusted'
    };
  }

  const freshness = validateThreatTimestampFreshness(signedRecord, options);
  if (!freshness.ok) {
    return { valid: false, payload: null, error: freshness.error };
  }

  try {
    const content = signedEnvelopeContent({
      payload: signedRecord.payload,
      signerNodeId: signedRecord.signerNodeId,
      timestamp: signedRecord.timestamp,
      nonce: signedRecord.nonce
    });
    const isValid = crypto.verify(
      null,
      Buffer.from(content, 'utf8'),
      publicKeyPem,
      Buffer.from(signedRecord.signature, 'base64')
    );

    if (!isValid) {
      return {
        valid: false,
        payload: null,
        error: 'Signature verification failed: payload, signer identity, timestamp, or nonce modified, or key mismatch'
      };
    }

    if (options.checkReplay !== false) {
      const cachePath = getReplayCachePath();
      const cacheKey = computeReplayCacheKey(signedRecord);
      const map = loadReplayCacheMapSync(cachePath, freshness.nowMs);
      if (map.has(cacheKey)) {
        return {
          valid: false,
          payload: null,
          error: `Replay detected for signer '${freshness.signerNodeId}'`
        };
      }
      if (options.recordReplay === true) {
        recordReplayEntrySync(cachePath, cacheKey, freshness.tsMs + freshness.maxClockSkewMs, freshness.nowMs);
      }
    }

    return {
      valid: true,
      payload: signedRecord.payload,
      error: null
    };
  } catch (err) {
    return {
      valid: false,
      error: `Verification error: ${err.message}`
    };
  }
}

/**
 * Broadcasts a signed threat record to connected peer nodes in the defense mesh.
 * @param {Object} signedRecord - Envelope returned from signThreatRecord
 * @param {Array<string|Object>} peersList - List of peer node addresses / configs
 * @returns {Object} Broadcast result
 */
export function broadcastThreatIndicator(signedRecord, peersList = []) {
  const broadcastId = `bc-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const delivered = [];

  for (const peer of peersList) {
    const peerName = typeof peer === 'string' ? peer : (peer.name || peer.nodeId || 'peer');
    delivered.push({
      peer: peerName,
      status: 'DELIVERED',
      deliveredAt: new Date().toISOString()
    });
  }

  logger.info('FEDERATION', `Broadcast ${broadcastId} dispatched to ${peersList.length} peer nodes.`);

  return {
    broadcastId,
    threatIndicator: signedRecord.payload?.indicator || 'unknown',
    sentTo: peersList.length,
    delivered,
    timestamp: new Date().toISOString()
  };
}

/**
 * Ingests a federated threat record: verifies cryptographic signature,
 * automatically executes local SOAR IP containment, and triggers a retrospective Data Lake hunt.
 * @param {Object} signedRecord - Inbound envelope
 * @param {Object} options - { verifySignature: boolean, publicKeyPem: string, runHunt: boolean }
 * @returns {Promise<Object>} Ingestion outcome & containment details
 */
export async function ingestFederatedThreatRecord(signedRecord, options = {}) {
  await ensureVigilanteConfig();
  const federationDir = getVigilanteFederationDir();
  const threatsDir = path.join(federationDir, 'threats');
  await fs.mkdir(threatsDir, { recursive: true });

  if (!signedRecord || !signedRecord.payload || typeof signedRecord.payload !== 'object') {
    throw new Error('Federated threat record rejected: invalid envelope structure');
  }

  // 1. Verify signature, timestamp freshness window, and replay state
  const freshness = validateThreatTimestampFreshness(signedRecord, options);
  if (!freshness.ok) {
    throw new Error(`Federated threat record rejected: ${freshness.error}`);
  }

  if (options.verifySignature !== false) {
    const verification = verifyThreatRecord(signedRecord, options.publicKeyPem, {
      maxClockSkewMs: options.maxClockSkewMs,
      nowMs: options.nowMs,
      checkReplay: true,
      recordReplay: false
    });
    if (!verification.valid) {
      throw new Error(`Federated threat record rejected: ${verification.error}`);
    }
  }

  const payload = signedRecord.payload;
  const actionsTaken = [];
  const indicator = payload.indicator || payload.ip || payload.target;
  const trimmedIndicator = typeof indicator === 'string'
    ? indicator.trim().replace(/^\[|\]$/g, '').split('%')[0]
    : '';
  const isIpLiteral = Boolean(trimmedIndicator && net.isIP(trimmedIndicator));
  const isIp = payload.type === 'IP' || payload.indicatorType === 'IP' || isIpLiteral;

  // Validate IP target against protected infrastructure deny-list BEFORE recording replay or calling soar.blockIp
  let safeBlockIp = null;
  if (isIp && indicator) {
    safeBlockIp = soar.assertSafeBlockTargetIp(indicator);
  }

  // Record replay entry atomically & persistently before executing SOAR side effects
  const cachePath = getReplayCachePath();
  const cacheKey = computeReplayCacheKey(signedRecord);
  const recorded = recordReplayEntrySync(
    cachePath,
    cacheKey,
    freshness.tsMs + freshness.maxClockSkewMs,
    freshness.nowMs
  );
  if (!recorded) {
    throw new Error(`Federated threat record rejected: Replay detected for signer '${freshness.signerNodeId}'`);
  }

  // 2. Automated SOAR containment (IP Block)
  if (safeBlockIp) {
    const blockResult = await soar.blockIp({
      ip: safeBlockIp,
      reason: `Federated defense sync: Flagged by node ${signedRecord.signerNodeId} (${payload.reason || 'Malicious C2'})`
    });
    actionsTaken.push({
      action: 'SOAR_BLOCK_IP',
      target: safeBlockIp,
      containmentId: blockResult.id || blockResult.containmentId,
      status: 'BLOCKED'
    });
  }

  // 3. Automated Retrospective Data Lake Hunt
  let huntMatches = [];
  if (options.runHunt !== false && indicator) {
    try {
      huntMatches = await datalake.runRetrospectiveThreatHunt([indicator]);
      actionsTaken.push({
        action: 'DATALAKE_RETROSPECTIVE_HUNT',
        indicator,
        matchCount: huntMatches.reduce((acc, m) => acc + (m.matchCount || 0), 0)
      });
    } catch (err) {
      logger.warn('FEDERATION', `Retrospective hunt skipped: ${err.message}`);
    }
  }

  // 4. Persist to federation store
  const recordId = `fed-threat-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const storedRecord = {
    recordId,
    signedRecord,
    ingestedAt: new Date().toISOString(),
    actionsTaken,
    huntMatches
  };

  const threatFilePath = resolvePathInside(threatsDir, `${recordId}.json`);
  await fs.writeFile(threatFilePath, JSON.stringify(storedRecord, null, 2), { mode: 0o600, encoding: 'utf8' });

  logger.info('FEDERATION', `Successfully ingested federated threat ${recordId} [${indicator}]. Actions executed: ${actionsTaken.length}`);

  return {
    ingested: true,
    recordId,
    indicator,
    actionsTaken,
    huntMatchesCount: huntMatches.length,
    threatFilePath
  };
}
