'use server';

import { execFileSync } from 'node:child_process';
import QRCode from 'qrcode';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { getCurrentDesiredState } from './agent';

// PKCS#8 DER prefix for a raw 32-byte X25519 private key.
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

/**
 * Derive the X25519 public key for a base64-encoded WireGuard private key
 * using Node crypto, without the `wg` CLI. Throws when the private key is
 * not a valid 32-byte base64 key.
 */
function deriveX25519PublicKey(privateKeyBase64: string): string {
  const rawPriv = Buffer.from(privateKeyBase64.trim(), 'base64');
  if (rawPriv.length !== 32) {
    throw new Error('WireGuard private key is not a 32-byte base64 key');
  }
  const der = Buffer.concat([X25519_PKCS8_PREFIX, rawPriv]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv);
  return pub.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
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

  // 1. Generate keys safely without shell invocation
  let privateKey = '';
  let publicKey = '';
  let serverPubKey = 'SERVER_PUBLIC_KEY_NOT_CONFIGURED';
  try {
    privateKey = execFileSync('wg', ['genkey'], { timeout: 1000, stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
    publicKey = execFileSync('wg', ['pubkey'], { input: privateKey + '\n', timeout: 1000, stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
    if (wgCfg?.privateKey) {
      serverPubKey = execFileSync('wg', ['pubkey'], { input: wgCfg.privateKey.trim() + '\n', timeout: 1000, stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
    }
  } catch {
    // Generate cryptographically valid x25519 Curve25519 keypair using Node.js crypto if wg CLI is absent
    const crypto = await import('node:crypto');
    const { publicKey: pubKeyObj, privateKey: privKeyObj } = crypto.generateKeyPairSync('x25519');
    const rawPriv = privKeyObj.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
    const rawPub = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
    privateKey = rawPriv.toString('base64');
    publicKey = rawPub.toString('base64');
    // The server public key is derivable from the configured server private
    // key without the `wg` CLI — never emit the placeholder key.
    if (wgCfg?.privateKey) {
      try {
        serverPubKey = deriveX25519PublicKey(wgCfg.privateKey);
      } catch {
        throw new Error('Configured WireGuard server private key is invalid: cannot derive its public key');
      }
    }
  }

  // Fail closed when the server key is genuinely unknown instead of handing
  // out a profile whose [Peer] PublicKey can never handshake.
  if (serverPubKey === 'SERVER_PUBLIC_KEY_NOT_CONFIGURED') {
    throw new Error(
      'WireGuard server public key is not configured: no server private key is set, so no usable client profile can be generated'
    );
  }

  // 2. Derive assigned IP and DNS from configured WireGuard interface address
  const ifaceCidr = wgCfg?.address || '10.99.0.1/24';
  const baseIp = ifaceCidr.split('/')[0] || '10.99.0.1';
  const octets = baseIp.split('.');
  const prefix3 = octets.length === 4 ? `${octets[0]}.${octets[1]}.${octets[2]}` : '10.99.0';
  const peerCount = (wgCfg?.peers?.length ?? 0) + 2;
  const assignedIp = `${prefix3}.${Math.min(254, peerCount)}/32`;
  const listenPort = wgCfg?.listenPort || 51820;
  const hostEndpoint = `${state.system?.hostname || 'vpn'}.${state.system?.domain || 'axonwall.local'}:${listenPort}`;

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
