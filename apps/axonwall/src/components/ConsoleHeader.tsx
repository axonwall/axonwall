'use client';

import { Shield, Clock, RotateCcw, CheckCircle2, LogOut, UserCheck, Loader2 } from 'lucide-react';
import { logoutAction } from '../server/auth';
import { confirmActiveRuleset, rollbackActiveRuleset, getAgentStatus } from '../server/agent';
import type { UserSession } from '@axonwall/lib/rbac';
import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
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
  pendingConfirm: initialPending = false,
  confirmDeadlineUnix: initialDeadline = 0,
  onConfirm,
  onRollback,
}: ConsoleHeaderProps) {
  const router = useRouter();
  const [isPending, setIsPending] = useState<boolean>(initialPending);
  const [deadline, setDeadline] = useState<number>(initialDeadline);
  const [timeLeft, setTimeLeft] = useState<number>(() => {
    if (!initialDeadline) return 0;
    return Math.max(0, initialDeadline - Math.floor(Date.now() / 1000));
  });
  const [isOperating, setIsOperating] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  // Sync with prop updates from Server Component
  useEffect(() => {
    setIsPending(initialPending);
    setDeadline(initialDeadline);
    if (initialDeadline) {
      setTimeLeft(Math.max(0, initialDeadline - Math.floor(Date.now() / 1000)));
    }
  }, [initialPending, initialDeadline]);

  // Status check function
  const checkStatus = useCallback(async () => {
    try {
      const status = await getAgentStatus();
      setIsPending(Boolean(status.pendingConfirm));
      const newDeadline = Number(status.confirmDeadlineUnix || 0);
      setDeadline(newDeadline);
      if (status.pendingConfirm && newDeadline) {
        setTimeLeft(Math.max(0, newDeadline - Math.floor(Date.now() / 1000)));
      } else {
        setTimeLeft(0);
      }
    } catch {}
  }, []);

  // Countdown timer
  useEffect(() => {
    if (!isPending || !deadline) return;

    const interval = setInterval(() => {
      const remaining = Math.max(0, deadline - Math.floor(Date.now() / 1000));
      setTimeLeft(remaining);

      // If timer hits zero, verify status with daemon/server
      if (remaining === 0) {
        checkStatus().then(() => router.refresh());
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isPending, deadline, checkStatus, router]);

  // Polling & Window event listener for status updates
  useEffect(() => {
    const handleRefreshEvent = () => {
      checkStatus();
    };

    window.addEventListener('axonwall:status-refresh', handleRefreshEvent);

    // Poll more frequently when pending confirm, slower when idle
    const pollInterval = setInterval(() => {
      checkStatus();
    }, isPending ? 3000 : 15000);

    return () => {
      window.removeEventListener('axonwall:status-refresh', handleRefreshEvent);
      clearInterval(pollInterval);
    };
  }, [isPending, checkStatus]);

  const handleConfirmAction = async () => {
    if (isOperating) return;
    setIsOperating(true);
    try {
      if (onConfirm) {
        await onConfirm();
      } else {
        const res = await confirmActiveRuleset();
        if (!res.success) {
          throw new Error(res.message || 'Confirmation failed');
        }
      }
      setIsPending(false);
      setTimeLeft(0);
      setFeedback('Configuration confirmed and promoted to Last-Known-Good.');
      setTimeout(() => setFeedback(null), 4000);
      router.refresh();
    } catch (err: any) {
      alert(`Confirm failed: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsOperating(false);
    }
  };

  const handleRollbackAction = async () => {
    if (isOperating) return;
    if (!confirm('Are you sure you want to rollback to the last-known-good configuration?')) {
      return;
    }
    setIsOperating(true);
    try {
      if (onRollback) {
        await onRollback();
      } else {
        const res = await rollbackActiveRuleset();
        if (!res.success) {
          throw new Error(res.message || 'Rollback failed');
        }
      }
      setIsPending(false);
      setTimeLeft(0);
      setFeedback('Rolled back to Last-Known-Good configuration.');
      setTimeout(() => setFeedback(null), 4000);
      router.refresh();
    } catch (err: any) {
      alert(`Rollback failed: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsOperating(false);
    }
  };

  return (
    <header className="bg-slate-900 border-b border-slate-800 px-6 py-3 sticky top-0 z-40">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-semibold text-sm text-slate-200">axonwall-appliance</span>
            <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
              v0.11.26
            </span>
          </div>

          {feedback && (
            <div className="flex items-center gap-2 bg-emerald-500/15 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs text-emerald-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{feedback}</span>
            </div>
          )}

          {!feedback && isPending && (
            <div className="flex items-center gap-3 bg-amber-500/10 border border-amber-500/30 px-3 py-1.5 rounded-lg text-xs text-amber-300 animate-pulse">
              <Clock className="w-4 h-4 text-amber-400 shrink-0" />
              <span>
                <strong>Commit-Confirm Active:</strong> Auto-rollback in {timeLeft}s unless confirmed!
              </span>
              <button
                type="button"
                onClick={handleConfirmAction}
                disabled={isOperating}
                className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-2.5 py-1 rounded flex items-center gap-1 font-medium transition cursor-pointer shadow-sm"
                title="Confirm and promote this configuration to Last-Known-Good"
              >
                {isOperating ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <CheckCircle2 className="w-3.5 h-3.5" />
                )}
                <span>Confirm</span>
              </button>
              <button
                type="button"
                onClick={handleRollbackAction}
                disabled={isOperating}
                className="bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white px-2.5 py-1 rounded flex items-center gap-1 font-medium transition cursor-pointer shadow-sm"
                title="Revert to previous Last-Known-Good configuration"
              >
                {isOperating ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <RotateCcw className="w-3.5 h-3.5" />
                )}
                <span>Rollback</span>
              </button>
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

