import { redirect } from 'next/navigation';
import { getSession, isPasswordChangeRequired } from '../../server/auth';
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

  const passwordChangeRequired = await isPasswordChangeRequired();
  const status = await getAgentStatus();

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      {passwordChangeRequired && <ForcePasswordChangeModal />}
      <ConsoleSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <ConsoleHeader
          session={session}
          pendingConfirm={status.pendingConfirm}
          confirmDeadlineUnix={status.confirmDeadlineUnix}
        />
        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
