'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  AlertCircle,
  CheckCircle2,
  Eye,
  EyeOff,
  Key,
  Loader2,
  Lock,
  Shield,
} from 'lucide-react';
import { Logo } from '@/components/Logo';

interface InvitePreview {
  status: 'valid' | 'expired' | 'used' | 'revoked' | 'invalid';
  username?: string;
  displayName?: string;
  mode?: 'onboard' | 'reset';
  expiresAt?: string;
  createStarterKey?: boolean;
  magicDnsDomain?: string;
  minPasswordLength?: number;
}

const WELCOME_STORAGE_KEY = 'axonwall_mesh_welcome';

export default function InviteRedeemPage() {
  const params = useParams<{ token: string }>();
  const router = useRouter();
  const token = typeof params?.token === 'string' ? params.token : '';

  const [preview, setPreview] = useState<InvitePreview | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setPreview({ status: 'invalid' });
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    fetch(`/api/v1/vpn/mesh/invites/preview?token=${encodeURIComponent(token)}`, {
      cache: 'no-store',
    })
      .then(async (res) => {
        const json = await res.json().catch(() => null);
        if (!res.ok || json?.status !== 'ok') {
          throw new Error(json?.error || `Failed to verify invite link (HTTP ${res.status})`);
        }
        if (active) setPreview(json.data);
      })
      .catch((err: any) => {
        if (active) setLoadError(err?.message || 'Unable to check invite link');
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [token]);

  const minLen = preview?.minPasswordLength ?? 12;
  const lengthOk = password.length >= minLen;
  const matches = password.length > 0 && password === confirmPassword;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    if (!lengthOk) {
      setSubmitError(`Password must be at least ${minLen} characters long.`);
      return;
    }
    if (!matches) {
      setSubmitError('Password and confirmation do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/v1/vpn/mesh/invites/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password, confirmPassword }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Activation failed (HTTP ${res.status})`);
      }

      if (json.starterKey) {
        try {
          sessionStorage.setItem(
            WELCOME_STORAGE_KEY,
            JSON.stringify({
              starterKey: json.starterKey,
              serverUrl: json.serverUrl || '',
              magicDnsDomain: json.magicDnsDomain || '',
              username: json.username || preview?.username || '',
            })
          );
        } catch {}
      }

      router.push(json.redirectTo || '/vpn');
    } catch (err: any) {
      setSubmitError(err?.message || 'Could not activate account');
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-8 space-y-6">
        <div className="flex flex-col items-center text-center space-y-2">
          <Logo variant="full" size="md" />
          <h1 className="text-xl font-bold text-white pt-2">
            {preview?.mode === 'reset'
              ? 'Reset Your Mesh VPN Password'
              : 'Activate Your Mesh VPN Account'}
          </h1>
          <p className="text-xs text-slate-400">
            Self-service private WireGuard mesh onboarding powered by Axonwall &amp; Headscale
          </p>
        </div>

        {loading ? (
          <div className="py-8 flex items-center justify-center gap-2.5 text-sm text-slate-400">
            <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
            <span>Verifying invitation link...</span>
          </div>
        ) : loadError ? (
          <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-sm text-red-200 flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span>{loadError}</span>
          </div>
        ) : preview?.status !== 'valid' ? (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-sm text-amber-200 space-y-1.5">
              <div className="font-semibold flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>
                  {preview?.status === 'used'
                    ? 'Invite Link Already Used'
                    : preview?.status === 'expired'
                      ? 'Invite Link Expired'
                      : preview?.status === 'revoked'
                        ? 'Invite Link Revoked'
                        : 'Invalid Invite Link'}
                </span>
              </div>
              <p className="text-xs text-amber-100/80">
                {preview?.status === 'used'
                  ? 'This single-use link has already been activated. Sign in with your username and password below.'
                  : 'Please ask your network administrator to generate a fresh Mesh VPN invite link.'}
              </p>
            </div>
            <Link
              href="/login"
              className="w-full bg-slate-800 hover:bg-slate-700 text-white font-medium py-2.5 rounded-lg text-sm flex items-center justify-center gap-2 transition"
            >
              <Key className="w-4 h-4" />
              <span>Go to Sign In</span>
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-1.5 text-xs">
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Account</span>
                <span className="font-semibold text-white">
                  {preview.displayName && preview.displayName !== preview.username
                    ? `${preview.displayName} (${preview.username})`
                    : preview.username}
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Username</span>
                <code className="font-mono text-emerald-400">{preview.username}</code>
              </div>
              {preview.magicDnsDomain && (
                <div className="flex items-center justify-between text-slate-300">
                  <span className="text-slate-400">Tailnet</span>
                  <code className="font-mono text-slate-200">{preview.magicDnsDomain}</code>
                </div>
              )}
              {preview.expiresAt && (
                <div className="flex items-center justify-between text-slate-400 tabular-nums">
                  <span>Invite expires</span>
                  <span>{new Date(preview.expiresAt).toLocaleString()}</span>
                </div>
              )}
            </div>

            {submitError && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{submitError}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Choose Password (min {minLen} chars)
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={minLen}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-10 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  placeholder="Create a strong password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={minLen}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  placeholder="Re-enter password"
                />
              </div>
            </div>

            <div className="flex flex-col gap-1 text-xs">
              <div className={`flex items-center gap-1.5 ${lengthOk ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>At least {minLen} characters</span>
              </div>
              <div className={`flex items-center gap-1.5 ${matches ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Passwords match</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting || !lengthOk || !matches}
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium py-2.5 rounded-lg text-sm flex items-center justify-center gap-2 transition cursor-pointer"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              <span>
                {submitting
                  ? 'Activating Account...'
                  : preview.mode === 'reset'
                    ? 'Update Password & Enter Portal'
                    : 'Activate & Enter Portal'}
              </span>
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
