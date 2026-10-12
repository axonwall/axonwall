'use client';

import React, { useState } from 'react';
import { ShieldAlert, KeyRound, Lock, ArrowRight, LogOut, CheckCircle2, AlertTriangle } from 'lucide-react';
import { changeAdminPasswordAction, logoutAction } from '../server/auth';

export function ForcePasswordChangeModal() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!currentPassword || !newPassword || !confirmPassword) {
      setError('Please fill in all password fields.');
      return;
    }

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long.');
      return;
    }

    if (newPassword === 'axonwall') {
      setError('You cannot reuse the default password. Please choose a secure password.');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('New password and confirmation do not match.');
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('currentPassword', currentPassword);
      formData.append('newPassword', newPassword);
      formData.append('confirmPassword', confirmPassword);

      const res = await changeAdminPasswordAction(formData);
      if (res?.error) {
        setError(res.error);
        setLoading(false);
      } else {
        setSuccess(true);
        setTimeout(() => {
          window.location.reload();
        }, 1200);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to update administrator password.');
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/90 backdrop-blur-md p-4">
      <div className="w-full max-w-md bg-slate-900 border border-amber-500/40 rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        <div className="bg-gradient-to-r from-amber-600/20 via-orange-600/10 to-transparent p-6 border-b border-slate-800">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-wide">
                Password Change Required
              </h2>
              <p className="text-xs text-amber-300/80 font-mono mt-0.5">
                First-time appliance administrator login
              </p>
            </div>
          </div>
        </div>

        <div className="p-6">
          {success ? (
            <div className="py-8 flex flex-col items-center justify-center text-center space-y-3">
              <CheckCircle2 className="w-12 h-12 text-emerald-400 animate-bounce" />
              <h3 className="text-lg font-semibold text-white">Password Updated</h3>
              <p className="text-sm text-slate-400">
                Administrator credentials updated successfully. Unlocking management console...
              </p>
            </div>
          ) : (
            <>
              <div className="mb-5 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-start space-x-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                <p className="text-xs text-amber-200 leading-relaxed">
                  For appliance security, you must replace the default administrator password
                  before accessing the Axonwall management console.
                </p>
              </div>

              {error && (
                <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs leading-relaxed">
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Current Password
                  </label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder="Enter current password (e.g. axonwall)"
                      required
                      className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 transition-colors"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    New Password (Min. 8 characters)
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Enter new strong password"
                      required
                      minLength={8}
                      className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 transition-colors"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Confirm New Password
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Re-enter new password"
                      required
                      minLength={8}
                      className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 transition-colors"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 flex items-center justify-center space-x-2 py-2.5 px-4 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white font-medium text-sm rounded-lg shadow-md hover:shadow-amber-500/20 disabled:opacity-50 transition-all cursor-pointer"
                >
                  <span>{loading ? 'Updating Credentials...' : 'Save Password & Continue'}</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>

              <div className="mt-5 pt-4 border-t border-slate-800 flex justify-center">
                <form action={logoutAction}>
                  <button
                    type="submit"
                    className="flex items-center space-x-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Log Out</span>
                  </button>
                </form>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
