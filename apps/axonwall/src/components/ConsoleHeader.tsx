'use client';

import { Shield, Clock, RotateCcw, CheckCircle2, LogOut, UserCheck } from 'lucide-react';
import { logoutAction } from '../server/auth';
import type { UserSession } from '@axonwall/lib/rbac';
import { useState, useEffect } from 'react';
import { ThemeSwitcher } from './ThemeSwitcher';

interface ConsoleHeaderProps {
  session: UserSession | null;
  pendingConfirm?: boolean;
  confirmDeadlineUnix?: number;
  onConfirm?: () => Promise<void>;
  onRollback?: () => Promise<void>;
}

export function ConsoleHeader({
  session,
  pendingConfirm = false,
  confirmDeadlineUnix = 0,
  onConfirm,
  onRollback,
}: ConsoleHeaderProps) {
  const [timeLeft, setTimeLeft] = useState<number>(0);

  useEffect(() => {
    if (!pendingConfirm || !confirmDeadlineUnix) return;

    const interval = setInterval(() => {
      const remaining = Math.max(0, confirmDeadlineUnix - Math.floor(Date.now() / 1000));
      setTimeLeft(remaining);
    }, 1000);

    return () => clearInterval(interval);
  }, [pendingConfirm, confirmDeadlineUnix]);

  return (
    <header className="bg-slate-900 border-b border-slate-800 px-6 py-3 sticky top-0 z-40">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-semibold text-sm text-slate-200">axonwall-appliance</span>
            <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
              v0.2.8
            </span>
          </div>

          {pendingConfirm && (
            <div className="flex items-center gap-3 bg-amber-500/10 border border-amber-500/30 px-3 py-1.5 rounded-lg text-xs text-amber-300 animate-pulse">
              <Clock className="w-4 h-4 text-amber-400" />
              <span>
                <strong>Commit-Confirm Active:</strong> Auto-rollback in {timeLeft}s unless confirmed!
              </span>
              {onConfirm && (
                <button
                  type="button"
                  onClick={onConfirm}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-2.5 py-1 rounded flex items-center gap-1 font-medium transition cursor-pointer"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Confirm
                </button>
              )}
              {onRollback && (
                <button
                  type="button"
                  onClick={onRollback}
                  className="bg-red-600 hover:bg-red-500 text-white px-2.5 py-1 rounded flex items-center gap-1 font-medium transition cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  Rollback
                </button>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-3">
          <ThemeSwitcher />

          {session && (
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              <span>{session.displayName || session.username}</span>
              <span className="bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 border border-slate-700">
                {session.roles[0] || 'admin'}
              </span>
            </div>
          )}

          <form action={logoutAction}>
            <button
              type="submit"
              className="text-slate-400 hover:text-red-400 text-xs flex items-center gap-1.5 py-1.5 px-3 rounded-lg hover:bg-slate-800/80 transition cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign out</span>
            </button>
          </form>
        </div>
      </div>
    </header>
  );
}
