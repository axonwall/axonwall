import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { ArrowLeft, LogOut, UserCheck } from 'lucide-react';
import { getSession, isPasswordChangeRequired, logoutAction } from '@/server/auth';
import { isConsoleUser } from '@/server/auth-guard';
import { Logo } from '@/components/Logo';
import { ThemeSwitcher } from '@/components/ThemeSwitcher';

export default async function PortalLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  if (!session) {
    redirect('/login');
  }

  const consoleUser = isConsoleUser(session);
  if (consoleUser && (session.passwordChangeRequired || (await isPasswordChangeRequired()))) {
    redirect('/lobby');
  }

  const roleLabel =
    session.roles[0] === 'vpn_user'
      ? 'VPN Member'
      : session.roles[0] === 'readonly'
        ? 'Auditor'
        : session.roles[0] === 'operator'
          ? 'Operator'
          : 'Admin';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <header className="bg-slate-900 border-b border-slate-800 px-4 sm:px-6 py-3 sticky top-0 z-40">
        <div className="max-w-5xl mx-auto flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-4">
            <Logo variant="full" size="sm" showSubtext={false} />
            <span className="hidden sm:inline text-xs font-medium text-slate-400 border-l border-slate-800 pl-4">
              Self-Service VPN Portal
            </span>
          </div>

          <div className="flex items-center gap-3">
            <ThemeSwitcher />

            {consoleUser && (
              <Link
                href="/lobby"
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1.5 rounded-lg flex items-center gap-1.5 transition"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Admin Console</span>
              </Link>
            )}

            <div className="flex items-center gap-2 text-xs text-slate-300">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              <span className="font-medium">{session.displayName || session.username}</span>
              <span className="bg-slate-800 px-2 py-0.5 rounded text-slate-300 border border-slate-700">
                {roleLabel}
              </span>
            </div>

            <form action={logoutAction}>
              <button
                type="submit"
                className="text-slate-400 hover:text-red-400 text-xs flex items-center gap-1.5 py-1.5 px-2.5 rounded-lg hover:bg-slate-800/80 transition cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign out</span>
              </button>
            </form>
          </div>
        </div>
      </header>

      <main className="flex-1 w-full max-w-5xl mx-auto px-4 sm:px-6 py-8">{children}</main>
    </div>
  );
}
