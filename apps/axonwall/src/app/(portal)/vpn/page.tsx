import { redirect } from 'next/navigation';
import { getSession } from '@/server/auth';
import { VpnPortalTabs } from '@/components/VpnPortalTabs';

export default async function VPNPortalPage() {
  const session = await getSession();
  if (!session) {
    redirect('/login');
  }

  const canAccessWireGuard =
    session.privileges?.includes('*') ||
    session.roles.includes('admin') ||
    session.roles.includes('operator');

  return <VpnPortalTabs canAccessWireGuard={Boolean(canAccessWireGuard)} />;
}
