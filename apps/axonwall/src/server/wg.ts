'use server';

import { execFileSync } from 'node:child_process';
import QRCode from 'qrcode';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { applyDesiredState, getCurrentDesiredState } from './agent';

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
    const derived = execFileSync('wg', ['pubkey'], { input: clean + '\n', timeout: 1000, stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
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

/** Server public key for the console WireGuard page (G3): null when no server key is configured. */
export async function getWireGuardServerPublicKey(): Promise<string | null> {
  const session = await getSession();
  assertActionPermitted(session);
  const state = await getCurrentDesiredState();
  const wgCfg: any = (state as any).wireguard || (state as any).vpn?.wireguard;
  if (!wgCfg?.privateKey) return null;
  return deriveWireGuardPublicKey(wgCfg.privateKey);
}

export async function generateWireGuardProfile() {
  const session = await getSession();
  assertActionPermitted(session, 'operator');

  const hasAccess =
    session.roles.includes('admin') ||
    session.roles.includes('operator') ||
    session.privileges?.includes('*') ||
    session.privileges?.includes('vpn.wireguard.write');
  if (!hasAccess) {
    throw new Error('Forbidden: Insufficient privileges to generate WireGuard profile');
  }

  const state = await getCurrentDesiredState();
  const wgCfg: any = (state as any).wireguard || (state as any).vpn?.wireguard;

  // N2: a profile is only useful if the server can actually handshake with
  // it. Without a configured server private key there is no real server
  // public key to put in [Peer] — fail instead of handing out a dead config.
  if (!wgCfg?.privateKey) {
    throw new Error('WireGuard server key is not configured: generate a server keypair on the WireGuard page before provisioning device profiles.');
  }
  const serverPubKey = await deriveWireGuardPublicKey(wgCfg.privateKey);
  if (!serverPubKey) {
    throw new Error('WireGuard server key is not usable: the stored server private key could not be parsed. Re-generate the server keypair before provisioning device profiles.');
  }

  // 1. Generate keys safely without shell invocation
  let privateKey = '';
  let publicKey = '';
  try {
    privateKey = execFileSync('wg', ['genkey'], { timeout: 1000, stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
    publicKey = execFileSync('wg', ['pubkey'], { input: privateKey + '\n', timeout: 1000, stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
  } catch {
    // Generate cryptographically valid x25519 Curve25519 keypair using Node.js crypto if wg CLI is absent
    const crypto = await import('node:crypto');
    const { publicKey: pubKeyObj, privateKey: privKeyObj } = crypto.generateKeyPairSync('x25519');
    const rawPriv = privKeyObj.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
    const rawPub = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
    privateKey = rawPriv.toString('base64');
    publicKey = rawPub.toString('base64');
  }

  // 2. Derive assigned IP and DNS from configured WireGuard interface address.
  // N2: allocate the first free host address from the set already in use
  // (server address + every registered peer) — never from peers.length,
  // which never grew because peers were never registered, so every profile
  // used to collide on the same address.
  const ifaceCidr = wgCfg?.address || '10.99.0.1/24';
  const baseIp = ifaceCidr.split('/')[0] || '10.99.0.1';
  const octets = baseIp.split('.');
  const prefix3 = octets.length === 4 ? `${octets[0]}.${octets[1]}.${octets[2]}` : '10.99.0';
  const usedLastOctets = new Set<number>();
  const collectOctet = (ip: string) => {
    const last = Number((ip || '').split('/')[0].split('.').pop());
    if (Number.isInteger(last) && last >= 0 && last <= 255) usedLastOctets.add(last);
  };
  collectOctet(baseIp);
  for (const peer of wgCfg?.peers ?? []) {
    for (const allowed of peer?.allowedIps ?? []) collectOctet(allowed);
  }
  let assignedOctet = -1;
  for (let candidate = 2; candidate <= 254; candidate++) {
    if (!usedLastOctets.has(candidate)) {
      assignedOctet = candidate;
      break;
    }
  }
  if (assignedOctet === -1) {
    throw new Error('No free WireGuard client address remains in the configured tunnel subnet.');
  }
  const assignedIp = `${prefix3}.${assignedOctet}/32`;
  const listenPort = wgCfg?.listenPort || 51820;
  const hostEndpoint = `${state.system?.hostname || 'vpn'}.${state.system?.domain || 'axonwall.local'}:${listenPort}`;

  // N2: register the peer in the desired state BEFORE issuing the profile,
  // so the server actually knows this peer and the next allocation sees it.
  // If registration fails (e.g. the caller is not an admin, or the apply is
  // refused), no profile is issued — a dead config must never be handed out.
  const username = ((session as any)?.username || 'portal-user').toString().replace(/[^A-Za-z0-9_-]/g, '') || 'portal-user';
  const existingNames = new Set((wgCfg?.peers ?? []).map((p: any) => p?.name));
  let peerName = `portal-${username}`;
  for (let suffix = 2; existingNames.has(peerName); suffix++) {
    peerName = `portal-${username}-${suffix}`;
  }
  const newPeer = {
    name: peerName,
    publicKey,
    allowedIps: [assignedIp],
    persistentKeepalive: 25,
    enabled: true,
  };
  try {
    await applyDesiredState({
      ...state,
      wireguard: {
        enabled: true,
        address: wgCfg.address || '10.99.0.1/24',
        listenPort: wgCfg.listenPort || 51820,
        privateKey: wgCfg.privateKey,
        peers: [...(wgCfg?.peers ?? []), newPeer],
      },
    });
  } catch (err: any) {
    throw new Error(`WireGuard peer could not be registered: ${err?.message || 'unknown error'}. No profile was issued — an admin must add this peer before it can connect.`);
  }

  const configStr = `[Interface]
PrivateKey = ${privateKey}
Address = ${assignedIp}
DNS = ${baseIp}

[Peer]
PublicKey = ${serverPubKey}
Endpoint = ${hostEndpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;

  // 3. Generate QR code
  const qrDataUrl = await QRCode.toDataURL(configStr, {
    errorCorrectionLevel: 'M',
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff'
    }
  });

  return {
    privateKey,
    publicKey,
    assignedIp,
    configStr,
    qrDataUrl
  };
}
