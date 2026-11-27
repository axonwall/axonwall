import { redirect } from 'next/navigation';
import { getSession, isPasswordChangeRequired } from '../../server/auth';
import { isVpnPortalOnlyUser } from '../../server/auth-guard';
import { ConsoleSidebar } from '../../components/ConsoleSidebar';
import { ConsoleHeader } from '../../components/ConsoleHeader';
import { ForcePasswordChangeModal } from '../../components/ForcePasswordChangeModal';
import { getAgentStatus } from '../../server/agent';

export default async function ConsoleLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getSession();
  if (!session) {
    redirect('/login');
  }
  if (isVpnPortalOnlyUser(session)) {
    redirect('/vpn');
  }

  const passwordChangeRequired = await isPasswordChangeRequired();
  const status = await getAgentStatus();

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      {passwordChangeRequired && <ForcePasswordChangeModal />}
      <ConsoleSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <ConsoleHeader
          session={{
            displayName: session.displayName || session.username,
            primaryRole: session.roles[0] || 'admin',
          }}
          pendingConfirm={status.pendingConfirm}
          confirmDeadlineUnix={status.confirmDeadlineUnix}
          daemonDown={status.daemonDown}
        />
        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
