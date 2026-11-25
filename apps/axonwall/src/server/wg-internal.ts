import { execFileSync } from 'node:child_process';
import { DesiredStateSchema, type WireGuardPeer } from '@axonwall/lib/schemas';
import { getDesiredStateInternal } from './desired-state-internal';
import { runDesiredStateApplyPipeline } from './apply-state-internal';

/**
 * Derive the X25519 public key for a base64 WireGuard private key.
 * Prefers the `wg` CLI; falls back to Node.js crypto (PKCS#8 wrapping of
 * the raw 32-byte key) when the CLI is absent. Returns null when the key
 * is missing or unparseable instead of emitting a placeholder.
 */
export async function deriveWireGuardPublicKey(privateKeyB64: string): Promise<string | null> {
  const clean = (privateKeyB64 || '').trim();
  if (!clean) return null;
  try {
    const derived = execFileSync('wg', ['pubkey'], {
      input: clean + '\n',
      timeout: 1000,
      stdio: ['pipe', 'pipe', 'ignore'],
      encoding: 'utf8',
    }).trim();
    if (derived) return derived;
  } catch {
    // wg CLI absent — fall through to the Node.js crypto derivation below.
  }
  try {
    const crypto = await import('node:crypto');
    const raw = Buffer.from(clean, 'base64');
    if (raw.length !== 32) return null;
    // PKCS#8 prefix for an X25519 private key, then the 32 raw bytes.
    const pkcs8Prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
    const privKeyObj = crypto.createPrivateKey({
      key: Buffer.concat([pkcs8Prefix, raw]),
      format: 'der',
      type: 'pkcs8',
    });
    const pubKeyObj = crypto.createPublicKey(privKeyObj);
    const rawPub = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
    return rawPub.toString('base64');
  } catch {
    return null;
  }
}

/**
 * Narrowly scoped internal WireGuard peer registration helper callable by
 * operator / `vpn.wireguard.write` sessions (W-M2). Modifies strictly the
 * new WireGuard peer entry on top of canonical desired state without exposing
 * full arbitrary-state admin apply permissions.
 */
export async function registerWireGuardPeerInternal(params: {
  newPeer: WireGuardPeer;
  expectedFingerprint?: string;
  actorUsername: string;
}): Promise<{ jobId?: string; pendingConfirm: boolean }> {
  const currentState = await getDesiredStateInternal();
  const wgCfg = currentState.wireguard;
  if (!wgCfg?.enabled) {
    throw new Error('WireGuard server is disabled — enable WireGuard before generating client profiles.');
  }
  if (!wgCfg?.privateKey) {
    throw new Error('WireGuard server key is not configured.');
  }

  const nextState = DesiredStateSchema.parse({
    ...currentState,
    wireguard: {
      ...wgCfg,
      enabled: true,
      address: wgCfg.address || '10.99.0.1/24',
      listenPort: wgCfg.listenPort || 51820,
      privateKey: wgCfg.privateKey,
      peers: [...(wgCfg.peers ?? []), params.newPeer],
    },
  });

  const applyRes = await runDesiredStateApplyPipeline(nextState, 120, {
    expectedFingerprint: params.expectedFingerprint,
    actorUsername: params.actorUsername,
  });

  return {
    jobId: applyRes.jobId,
    pendingConfirm: !applyRes.devMode,
  };
}
