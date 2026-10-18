'use server';

import { execFileSync } from 'node:child_process';
import QRCode from 'qrcode';
import { getSession } from './auth';

export async function generateWireGuardProfile() {
  const session = await getSession();
  if (!session) {
    throw new Error('Unauthorized');
  }
  if (session.passwordChangeRequired) {
    throw new Error('Forbidden: Password change required before generating VPN profile');
  }

  const hasAccess =
    session.roles.includes('admin') ||
    session.roles.includes('operator') ||
    session.privileges?.includes('*') ||
    session.privileges?.includes('vpn.wireguard.write');
  if (!hasAccess) {
    throw new Error('Forbidden: Insufficient privileges to generate WireGuard profile');
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

  // 2. Mock assigning IP address from pool for the user
  const assignedIp = '10.99.1.50/32';

  const configStr = `[Interface]
PrivateKey = ${privateKey}
Address = ${assignedIp}
DNS = 10.99.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = vpn.axonwall.local:51820
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
