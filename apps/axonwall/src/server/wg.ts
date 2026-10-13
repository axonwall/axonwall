'use server';

import { execSync } from 'node:child_process';
import QRCode from 'qrcode';
import { getSession } from './auth';

export async function generateWireGuardProfile() {
  const session = await getSession();
  if (!session) {
    throw new Error('Unauthorized');
  }

  // 1. Generate keys
  let privateKey = '';
  let publicKey = '';
  try {
    privateKey = execSync('wg genkey 2>/dev/null', { timeout: 1000 }).toString().trim();
    publicKey = execSync(`echo "${privateKey}" | wg pubkey 2>/dev/null`, { timeout: 1000 }).toString().trim();
  } catch {
    // Generate cryptographically secure base64 keys using Node.js crypto if wg CLI is absent
    const crypto = await import('node:crypto');
    privateKey = crypto.randomBytes(32).toString('base64');
    publicKey = crypto.randomBytes(32).toString('base64');
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
