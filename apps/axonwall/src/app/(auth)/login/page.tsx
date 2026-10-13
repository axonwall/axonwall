'use client';

import { useActionState } from 'react';
import { Shield, Lock, User, AlertCircle, Key, Building2 } from 'lucide-react';
import { loginAction } from '../../../server/auth';
import { Logo } from '../../../components/Logo';

export default function LoginPage() {
  const [state, formAction, isPending] = useActionState(loginAction, null);

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-8">
        <div className="flex flex-col items-center mb-8">
          <Logo variant="full" size="lg" className="mb-2" />
        </div>

        {state?.error && (
          <div className="mb-6 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2 text-sm text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{state.error}</span>
          </div>
        )}

        <form action={formAction} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Username
            </label>
            <div className="relative">
              <User className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
              <input
                type="text"
                name="username"
                required
                defaultValue="admin"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500"
                placeholder="LDAP or local admin"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
              <input
                type="password"
                name="password"
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              MFA / Authenticator Code
            </label>
            <div className="relative">
              <Key className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
              <input
                type="text"
                name="totpCode"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500"
                placeholder="Optional (6-digit code)"
                pattern="\d{6}"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isPending}
            className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer shadow-lg shadow-emerald-950"
          >
            <Key className="w-4 h-4" />
            <span>{isPending ? 'Authenticating...' : 'Sign in'}</span>
          </button>
        </form>

        <div className="relative my-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-slate-800"></div>
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-slate-900 px-2 text-slate-500 font-medium">Or continue with</span>
          </div>
        </div>

        <a
          href="/api/auth/sso/login"
          className="w-full bg-slate-950 hover:bg-slate-800/80 text-slate-200 border border-slate-800 font-medium py-2.5 rounded-lg transition flex items-center justify-center gap-2.5 cursor-pointer shadow-sm text-sm"
        >
          <Building2 className="w-4 h-4 text-emerald-400" />
          <span>Single Sign-On (Entra ID / Okta / OIDC)</span>
        </a>

        <div className="mt-8 pt-6 border-t border-slate-800/80 text-center">
          <p className="text-xs text-slate-500">
            Authentication verified against internal/external LDAP, OIDC SSO, or local root break-glass fallback.
          </p>
        </div>
      </div>
    </div>
  );
}
