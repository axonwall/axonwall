import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { createEncryptedBackup } from '@/server/backup';
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';

// Sample baseline appliance state if not yet loaded from DB
const BASELINE_STATE: DesiredState = DesiredStateSchema.parse({
  version: 1,
  system: {
    hostname: 'axonwall-core',
    domain: 'axonwall.local',
    dnsServers: ['1.1.1.1', '8.8.8.8'],
    timezone: 'UTC',
    flowtableOffload: true,
    antiLockout: {
      enabled: true,
      interface: 'lan',
      ports: [22, 80, 443, 8443, 3000],
    },
  },
  interfaces: [
    { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, mtu: 1500, description: 'WAN Gateway' },
    { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.100.1/24', mtu: 1500, description: 'LAN Network' },
  ],
});

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    return new NextResponse('Unauthorized: Admin access required', { status: 401 });
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const passphrase = body.passphrase || 'axonwall-default-recovery-passphrase';

  try {
    const { id, buffer } = await createEncryptedBackup(BASELINE_STATE, passphrase);

    return new NextResponse(new Uint8Array(buffer), {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${id}.axb"`,
        'Content-Length': buffer.length.toString(),
      },
    });
  } catch (err: any) {
    return new NextResponse(err?.message || 'Failed to generate backup', { status: 500 });
  }
}
